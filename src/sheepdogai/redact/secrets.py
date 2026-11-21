"""Secret redaction. Runs before anything is hashed, logged or sent anywhere.

Patterns are linear-time (bounded quantifiers, no nested repetition). Redaction is
idempotent. This is best-effort pattern matching, not a guarantee: see docs/limitations.md.
"""

from __future__ import annotations

import re
from typing import Any

MAX_STR = 1_000_000  # chars scanned in full; the remainder is replaced, never passed through

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----"
            r"(?:[\s\S]{0,20000}?-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----|[A-Za-z0-9+/=\s]{0,20000})"
        ),
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{30,255})\b"),
    ),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,200}\b")),
    ("api_key_sk", re.compile(r"\bsk-[A-Za-z0-9_-]{20,200}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("bearer", re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}")),
    (
        "url_credentials",
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,12}://)[^\s/:@]{1,100}:[^\s/@]{1,200}@"),
    ),
    (
        "assignment",
        re.compile(
            r"(?i)\b([A-Za-z0-9_.-]{0,40}(?:api[_-]?key|secret|token|passwd|password|pwd|"
            r"private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]{0,20})(\s*[=:]\s*)"
            r"(?:\"[^\"\n]{1,500}\"|'[^'\n]{1,500}'|[^\s\"';&|]{1,500})"
        ),
    ),
]

_SENSITIVE_KEY = re.compile(
    r"(?i)(api[_-]?key|secret|token|passw(or)?d|authorization|private[_-]?key|credential|cookie)"
)


def redact_text(s: str) -> str:
    """Replace secrets in ``s`` with ``[REDACTED:<kind>]`` markers."""
    if len(s) > MAX_STR:
        head = redact_text(s[:MAX_STR])
        return head + f"[TRUNCATED:{len(s) - MAX_STR} chars not scanned or stored]"
    for kind, pat in _PATTERNS:
        if kind == "assignment":
            s = pat.sub(lambda m, k=kind: f"{m.group(1)}{m.group(2)}[REDACTED:{k}]", s)
        elif kind == "bearer":
            s = pat.sub(lambda m, k=kind: f"{m.group(1)} [REDACTED:{k}]", s)
        elif kind == "url_credentials":
            s = pat.sub(lambda m, k=kind: f"{m.group(1)}[REDACTED:{k}]@", s)
        else:
            s = pat.sub(f"[REDACTED:{kind}]", s)
    return s


def redact_obj(obj: Any, _key: str | None = None) -> Any:
    """Recursively redact strings in JSON-like data; values under sensitive keys are masked."""
    if isinstance(obj, str):
        if _key is not None and _SENSITIVE_KEY.search(_key) and "[REDACTED" not in obj:
            return "[REDACTED:sensitive_key]"
        return redact_text(obj)
    if isinstance(obj, dict):
        return {str(k): redact_obj(v, str(k)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, _key) for v in obj]
    return obj
