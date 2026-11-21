"""Hash-chain primitives. Pure functions, no I/O."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from sheepdogai.core.canonical import canonical_json, sha256_hex

GENESIS = "0" * 64


def record_hash(prev_hash: str, body: dict[str, Any]) -> str:
    """hash = sha256(prev_hash || canonical_json(body))."""
    return sha256_hex(prev_hash + canonical_json(body))


def make_record(index: int, kind: str, data: dict[str, Any], prev_hash: str) -> dict[str, Any]:
    """Build a full record (body + prev_hash + hash)."""
    body = {"index": index, "kind": kind, "data": data}
    return {**body, "prev_hash": prev_hash, "hash": record_hash(prev_hash, body)}


def encode_line(rec: dict[str, Any]) -> bytes:
    """Canonical one-line encoding of a record, newline-terminated."""
    return (canonical_json(rec) + "\n").encode("ascii")


def decode_line(line: bytes) -> dict[str, Any]:
    """Decode and check a line is exactly the canonical encoding; raises ValueError."""
    if not line.endswith(b"\n"):
        raise ValueError("line not newline-terminated (truncated?)")
    text = line[:-1].decode("ascii")
    rec = json.loads(text)
    if not isinstance(rec, dict) or canonical_json(rec) != text:
        raise ValueError("line is not canonical JSON")
    return rec


def sign_checkpoint(head_hash: str, key: bytes) -> str:
    """Optional extension point: HMAC-SHA256 over the head hash with a local key.

    Off by default. HMAC is symmetric, so this detects tampering by anyone without the key;
    use an asymmetric signature (e.g. Ed25519) for third-party verification.
    """
    return hmac.new(key, head_hash.encode("ascii"), hashlib.sha256).hexdigest()


def verify_checkpoint(head_hash: str, key: bytes, sig: str) -> bool:
    """Constant-time check of :func:`sign_checkpoint`."""
    return hmac.compare_digest(sign_checkpoint(head_hash, key), sig)
