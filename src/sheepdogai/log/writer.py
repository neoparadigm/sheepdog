"""Append-only log writer: O_APPEND, fsync, 0600 files, redaction before hashing."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
from typing import Any

from sheepdogai.constants import SCHEMA_VERSION
from sheepdogai.core.errors import LogError
from sheepdogai.log import chain
from sheepdogai.redact.secrets import redact_obj

MAX_RECORD_BYTES = 256 * 1024


class RunLogWriter:
    """Writes one JSON Lines file per run. The first record anchors to the policy hash."""

    def __init__(self, directory: Path, run_id: str, policy_hash: str) -> None:
        if not run_id or "/" in run_id or "\\" in run_id or run_id.startswith("."):
            raise LogError(f"invalid run id {run_id!r}")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        self.path = directory / f"{run_id}.jsonl"
        self.head_path = directory / f"{run_id}.jsonl.head"
        self._fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.fchmod(self._fd, 0o600)
        self._index, self._prev = self._resume()
        if self._index == 0:
            self.append(
                "anchor",
                {"policy_hash": policy_hash, "schema_version": SCHEMA_VERSION, "run_id": run_id},
            )

    def _resume(self) -> tuple[int, str]:
        last: bytes | None = None
        with open(self.path, "rb") as f:
            for line in f:
                last = line
        if last is None:
            return 0, chain.GENESIS
        try:
            rec = chain.decode_line(last)
            return int(rec["index"]) + 1, str(rec["hash"])
        except (ValueError, KeyError) as e:
            raise LogError(f"existing log {self.path} is corrupt; refusing to append: {e}") from e

    def append(self, kind: str, data: dict[str, Any]) -> dict[str, Any]:
        """Redact, chain and durably append one record. Raises LogError on any failure."""
        clean = redact_obj(data)
        rec = chain.make_record(self._index, kind, clean, self._prev)
        line = chain.encode_line(rec)
        if len(line) > MAX_RECORD_BYTES:
            rec = chain.make_record(
                self._index, kind, {"truncated": True, "original_bytes": len(line)}, self._prev
            )
            line = chain.encode_line(rec)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX)
            try:
                n = os.write(self._fd, line)
                if n != len(line):
                    raise OSError("short write")
                os.fsync(self._fd)
            finally:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            self._write_head(rec)
        except OSError as e:
            raise LogError(f"cannot write log: {e}") from e
        self._index += 1
        self._prev = str(rec["hash"])
        return rec

    def _write_head(self, rec: dict[str, Any]) -> None:
        tmp = self.head_path.with_suffix(".head.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps({"index": rec["index"], "hash": rec["hash"]}).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.head_path)

    def close(self) -> None:
        """Close the file descriptor."""
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1
