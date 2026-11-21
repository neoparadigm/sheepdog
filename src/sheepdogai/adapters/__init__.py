"""Adapters: one per agent CLI. Shared helpers live here."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sheepdogai.core.adapter import Adapter
from sheepdogai.core.canonical import uuid7
from sheepdogai.core.errors import ParseError
from sheepdogai.core.events import Provenance, Source, ToolCallEvent, ToolKind, ToolRef

MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
UNTRUSTING_KINDS = {"network"}


def load_json_object(raw: bytes) -> dict[str, Any]:
    """Parse a hook payload into a JSON object or raise ParseError (never anything else)."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ParseError("payload is not bytes")
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ParseError(f"payload larger than {MAX_PAYLOAD_BYTES} bytes")
    if not raw.strip():
        raise ParseError("empty payload")
    try:
        obj = json.loads(raw)
    except (ValueError, RecursionError, UnicodeDecodeError) as e:
        raise ParseError(f"invalid JSON: {type(e).__name__}") from e
    if not isinstance(obj, dict):
        raise ParseError("payload is not a JSON object")
    return obj


def req_str(obj: dict[str, Any], key: str) -> str:
    """Return a required non-empty string field or raise ParseError."""
    v = obj.get(key)
    if not isinstance(v, str) or not v:
        raise ParseError(f"missing or invalid field {key!r}")
    return v


def build_event(
    *,
    source: Source,
    session_id: str,
    cwd: str | None,
    tool_name: str,
    kind: ToolKind,
    args: dict[str, Any],
    agent_id: str,
    untrusted: bool = False,
    raw_ref: str | None = None,
) -> ToolCallEvent:
    """Create the standard event. ``seq`` is 0 here; the session stamps the real value."""
    return ToolCallEvent(
        event_id=uuid7(),
        run_id=session_id,
        session_id=session_id,
        seq=0,
        ts=datetime.now(UTC),
        source=source,
        agent_id=agent_id,
        tool=ToolRef(name=tool_name, kind=kind),
        args=args,
        cwd=cwd,
        provenance=Provenance(trusted=not untrusted, untrusted_content_seen=untrusted),
        raw_ref=raw_ref,
    )


def get_adapter(name: str, *, experimental: bool = False) -> Adapter:
    """Return an adapter instance by CLI name. Experimental adapters need the flag."""
    from sheepdogai.adapters.claude_code import ClaudeCodeAdapter
    from sheepdogai.adapters.codex import CodexAdapter
    from sheepdogai.adapters.gemini import GeminiAdapter

    if name == "claude":
        return ClaudeCodeAdapter()
    if name == "gemini":
        return GeminiAdapter()
    if name == "codex":
        if not experimental:
            raise ParseError("the codex adapter is experimental; pass --experimental to use it")
        return CodexAdapter()
    raise ParseError(f"unknown adapter {name!r}")
