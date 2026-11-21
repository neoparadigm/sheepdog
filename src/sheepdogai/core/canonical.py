"""Canonical JSON and hashing helpers. Stable bytes for stable input."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from typing import Any


def canonical_json(obj: Any) -> str:
    """Return deterministic JSON: sorted keys, no whitespace, ASCII only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data: str | bytes) -> str:
    """Return the hex SHA-256 digest of ``data`` (str is UTF-8 encoded)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def uuid7() -> str:
    """Return a time-ordered UUIDv7 string (RFC 9562), built here for Python 3.11+."""
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= ((rand >> 68) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= rand & ((1 << 62) - 1)
    return str(uuid.UUID(int=value))
