"""Recompute the hash chain and report the first broken record."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sheepdogai.log import chain


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of ``verify_log``. ``broken_at`` is the 0-based index of the first bad record."""

    ok: bool
    records: int
    broken_at: int | None = None
    reason: str = ""
    sealed: bool = False  # True when a .head sidecar confirmed the tail


def verify_log(path: Path) -> VerifyResult:
    """Verify one run log. Detects flips, deletions, reordering and truncation."""
    try:
        data = path.read_bytes()
    except OSError as e:
        return VerifyResult(False, 0, None, f"cannot read log: {e}")
    lines = data.splitlines(keepends=True)
    prev = chain.GENESIS
    for i, line in enumerate(lines):
        try:
            rec = chain.decode_line(line)
        except (ValueError, UnicodeDecodeError) as e:
            return VerifyResult(False, i, i, f"unreadable record: {e}")
        body_keys = {"index", "kind", "data", "prev_hash", "hash"}
        if set(rec) != body_keys:
            return VerifyResult(False, i, i, "unexpected record fields")
        if rec["index"] != i:
            return VerifyResult(False, i, i, f"index {rec['index']} where {i} expected")
        if rec["prev_hash"] != prev:
            return VerifyResult(False, i, i, "prev_hash does not match previous record")
        body = {"index": rec["index"], "kind": rec["kind"], "data": rec["data"]}
        if chain.record_hash(prev, body) != rec["hash"]:
            return VerifyResult(False, i, i, "hash mismatch (record modified)")
        if i == 0 and rec["kind"] != "anchor":
            return VerifyResult(False, i, i, "first record is not the policy anchor")
        prev = str(rec["hash"])
    if not lines:
        return VerifyResult(False, 0, 0, "empty log")
    head = path.with_name(path.name + ".head")
    sealed = False
    if head.exists():
        try:
            h = json.loads(head.read_text())
        except (OSError, ValueError):
            return VerifyResult(False, len(lines), len(lines), "head sidecar unreadable")
        if h.get("index") != len(lines) - 1 or h.get("hash") != prev:
            return VerifyResult(
                False,
                len(lines),
                min(len(lines), int(h.get("index", 0)) + 1)
                if isinstance(h.get("index"), int)
                else len(lines),
                f"log ends at record {len(lines) - 1} but head sidecar says {h.get('index')} "
                "(truncated or sidecar edited)",
            )
        sealed = True
    return VerifyResult(True, len(lines), None, "", sealed)
