"""The one standard event every adapter produces. Frozen and versioned."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ToolKind = Literal["shell", "file_read", "file_write", "network", "mcp", "other"]
Source = Literal["claude_code", "codex", "gemini", "framework", "scripted"]


class ToolRef(BaseModel):
    """Name and normalised kind of the tool being called."""

    model_config = ConfigDict(frozen=True)
    name: str
    kind: ToolKind


class Provenance(BaseModel):
    """Trust information. ``untrusted_content_seen`` is set by the harness or adapter."""

    model_config = ConfigDict(frozen=True)
    trusted: bool = True
    untrusted_content_seen: bool = False
    origin_hints: list[str] = Field(default_factory=list)


class ToolCallEvent(BaseModel):
    """A single normalised tool call. ``args`` are redacted before logging."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal["1"] = "1"
    event_id: str
    run_id: str
    session_id: str
    seq: int
    ts: datetime
    source: Source
    agent_id: str
    tool: ToolRef
    args: dict[str, Any]
    cwd: str | None = None
    provenance: Provenance = Field(default_factory=Provenance)
    raw_ref: str | None = None
