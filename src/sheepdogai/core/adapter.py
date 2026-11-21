"""Adapter protocol: one adapter per agent CLI or framework."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict

from sheepdogai.core.events import ToolCallEvent
from sheepdogai.core.verdict import Verdict


class AdapterCapabilities(BaseModel):
    """What the host CLI lets the adapter do."""

    model_config = ConfigDict(frozen=True)
    can_block: bool
    can_ask: bool
    sees_mcp: bool
    sees_file_edits: bool


class AdapterResponse(BaseModel):
    """What the hook process must emit: stdout text, stderr text and an exit code."""

    model_config = ConfigDict(frozen=True)
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


class Adapter(Protocol):
    """Parse a raw hook payload into an event and render a verdict in the CLI's format."""

    name: str
    capabilities: AdapterCapabilities

    def parse(self, raw: bytes) -> ToolCallEvent:
        """Parse ``raw``; raise ``ParseError`` on anything unexpected."""
        ...

    def respond(self, v: Verdict) -> AdapterResponse:
        """Render a verdict. Must never produce an allow for a deny."""
        ...

    def fail_closed(self, reason: str) -> AdapterResponse:
        """Render a deny for when no verdict could be produced."""
        ...
