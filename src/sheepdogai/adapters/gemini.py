"""Gemini CLI adapter: BeforeTool hook.

Sources (checked 2026-11-21):
* https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md
* https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/tools.md

Verified from those pages: JSON on stdin (``session_id``, ``transcript_path``, ``cwd``,
``hook_event_name``, ``timestamp``, plus ``tool_name``, ``tool_input``, optional ``mcp_context``);
output JSON ``{"decision": "allow"|"deny"|"block", "reason": ...}`` on exit 0, or exit 2 with the
reason on stderr ("System Block"). Other exit codes are warnings and the CLI continues, so every
failure path here exits 2. MCP tools are named ``mcp_<server>_<tool>``. There is no documented
"ask" for BeforeTool, so ``can_ask`` is False and the engine downgrades ask to deny.
Tool names and argument names (``run_shell_command.command``, ``read_file.file_path``,
``write_file``/``replace``, ``web_fetch``) are taken from tools.md.
"""

from __future__ import annotations

import json
from typing import Any

from sheepdogai.adapters import build_event, load_json_object, req_str
from sheepdogai.core.adapter import AdapterCapabilities, AdapterResponse
from sheepdogai.core.errors import ParseError
from sheepdogai.core.events import ToolCallEvent, ToolKind
from sheepdogai.core.verdict import Action, Verdict

SHELL = {"run_shell_command"}
READ = {
    "read_file",
    "read_many_files",
    "list_directory",
    "glob",
    "grep_search",
    "search_file_content",
    "read_mcp_resource",
    "list_mcp_resources",
}
WRITE = {"write_file", "replace"}
NET = {"web_fetch", "google_web_search"}


def classify(name: str) -> ToolKind:
    """Map a Gemini CLI tool name to a normalised kind."""
    if name in SHELL:
        return "shell"
    if name in READ:
        return "file_read"
    if name in WRITE:
        return "file_write"
    if name in NET:
        return "network"
    if name.startswith("mcp_"):
        return "mcp"
    return "other"


class GeminiAdapter:
    """Adapter for Gemini CLI's BeforeTool hook."""

    name = "gemini"
    capabilities = AdapterCapabilities(
        can_block=True, can_ask=False, sees_mcp=True, sees_file_edits=True
    )

    def parse(self, raw: bytes) -> ToolCallEvent:
        """Parse a BeforeTool payload."""
        obj = load_json_object(raw)
        if obj.get("hook_event_name") != "BeforeTool":
            raise ParseError(f"unexpected hook_event_name {obj.get('hook_event_name')!r}")
        tool = req_str(obj, "tool_name")
        session = req_str(obj, "session_id")
        ti = obj.get("tool_input")
        if not isinstance(ti, dict):
            raise ParseError("tool_input is not an object")
        args: dict[str, Any] = dict(ti)
        for k in ("file_path", "dir_path", "path"):
            if isinstance(ti.get(k), str):
                args.setdefault("path", ti[k])
        if tool == "web_fetch" and isinstance(ti.get("prompt"), str):
            args.setdefault("url", ti["prompt"])  # tools.md: URLs are embedded in the prompt
        cwd = obj.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ParseError("cwd is not a string")
        return build_event(
            source="gemini",
            session_id=session,
            cwd=cwd,
            tool_name=tool,
            kind=classify(tool),
            args=args,
            agent_id="gemini",
        )

    def respond(self, v: Verdict) -> AdapterResponse:
        """Deny exits 2 with the reason; anything else prints an empty JSON object."""
        if v.action is Action.DENY or v.action is Action.ASK:
            rid = f" [{v.rule_id}]" if v.rule_id else ""
            return AdapterResponse(stderr=f"sheepdog: {v.reason or 'denied'}{rid}", exit_code=2)
        return AdapterResponse(stdout=json.dumps({}), exit_code=0)

    def fail_closed(self, reason: str) -> AdapterResponse:
        """Exit 2 with a non-empty reason."""
        return AdapterResponse(
            stderr=f"sheepdog: {reason or 'failing closed'} (fail closed)", exit_code=2
        )
