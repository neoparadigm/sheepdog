"""Template for a framework adapter (LangGraph, OpenAI Agents SDK, ...). Out of scope for v0.1.

This module documents the contract and nothing more. To add a framework:

1. Implement ``sheepdogai.core.adapter.Adapter``:
   * ``name`` and ``capabilities`` (``can_block``, ``can_ask``, ``sees_mcp``, ``sees_file_edits``),
     declared honestly: if the framework cannot ask a human, ``can_ask`` is False and the engine
     will downgrade ask to deny.
   * ``parse(raw) -> ToolCallEvent``: raise only ``ParseError`` (never any other exception) on
     malformed input; accept inputs up to 16 MiB; normalise the call into ``tool.kind`` and
     ``args`` (use the keys ``command``, ``path``, ``url`` when they exist).
   * ``respond(verdict) -> AdapterResponse`` and ``fail_closed(reason)``: a non-allow verdict must
     block, and a failure to decide must block (exit code 2 with a non-empty reason).
2. Record fixtures under ``tests/fixtures/<name>/`` from the framework's documented payloads, cite
   the documentation URL and date in the module docstring, and mark anything unconfirmed.
3. Register the adapter in ``sheepdogai.adapters.get_adapter`` behind the experimental flag, and add
   it to ``tests/conformance/test_adapters.py``: every adapter must pass the same suite.
"""

from __future__ import annotations

from sheepdogai.core.adapter import AdapterCapabilities, AdapterResponse
from sheepdogai.core.events import ToolCallEvent
from sheepdogai.core.verdict import Verdict


class TemplateAdapter:
    """Skeleton showing the shape of an adapter; it does nothing."""

    name = "template"
    capabilities = AdapterCapabilities(
        can_block=False, can_ask=False, sees_mcp=False, sees_file_edits=False
    )

    def parse(self, raw: bytes) -> ToolCallEvent:
        """Parse the framework's payload (not implemented)."""
        raise NotImplementedError

    def respond(self, v: Verdict) -> AdapterResponse:
        """Render a verdict in the framework's format (not implemented)."""
        raise NotImplementedError

    def fail_closed(self, reason: str) -> AdapterResponse:
        """Render a block for when no verdict could be produced (not implemented)."""
        raise NotImplementedError
