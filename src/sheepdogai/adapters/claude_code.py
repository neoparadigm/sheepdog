"""Claude Code adapter: PreToolUse hook.

Source: https://code.claude.com/docs/en/hooks  (checked 2026-11-21)

Verified from that page:
* Input is one JSON object on stdin with ``session_id``, ``cwd``, ``permission_mode``,
  ``hook_event_name`` ("PreToolUse"), ``tool_name``, ``tool_input``, ``tool_use_id``; MCP tools
  add ``mcp_server``. File tools carry an absolute ``tool_input.file_path``.
* Output: exit 2 blocks and stderr is shown to Claude as the reason; or exit 0 with
  ``{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision":
  "allow|deny|ask", "permissionDecisionReason": ...}}``. Precedence across hooks: deny > defer >
  ask > allow.
* Exit 0 with output that is not valid JSON, and any exit code other than 0 or 2, are
  *non-blocking* errors (the call proceeds). Therefore every failure path here exits 2.

Design choices:
* deny -> exit 2 with the reason on stderr (does not depend on JSON parsing).
* ask  -> ``permissionDecision: "ask"``.
* allow -> exit 0 with no output. sheepdog never *grants* permission ("allow" in the docs skips
  the user's own permission prompt); it only restricts.
"""

from __future__ import annotations

import json
from typing import Any

from sheepdogai.adapters import build_event, load_json_object, req_str
from sheepdogai.core.adapter import AdapterCapabilities, AdapterResponse
from sheepdogai.core.errors import ParseError
from sheepdogai.core.events import ToolCallEvent, ToolKind
from sheepdogai.core.verdict import Action, Verdict

SHELL = {"Bash", "PowerShell", "Monitor"}
READ = {"Read", "Glob", "Grep", "NotebookRead", "LS"}
WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
NET = {"WebFetch", "WebSearch"}


def classify(name: str) -> ToolKind:
    """Map a Claude Code tool name to a normalised kind."""
    if name in SHELL:
        return "shell"
    if name in READ:
        return "file_read"
    if name in WRITE:
        return "file_write"
    if name in NET:
        return "network"
    if name.startswith("mcp__"):
        return "mcp"
    return "other"


def reason_text(v: Verdict) -> str:
    """Human-readable reason including the rule id."""
    rid = f" [{v.rule_id}]" if v.rule_id else ""
    return f"sheepdog: {v.reason or v.action.label}{rid}"


class ClaudeCodeAdapter:
    """Adapter for Claude Code's PreToolUse hook."""

    name = "claude_code"
    capabilities = AdapterCapabilities(
        can_block=True, can_ask=True, sees_mcp=True, sees_file_edits=True
    )

    def parse(self, raw: bytes) -> ToolCallEvent:
        """Parse a PreToolUse payload."""
        obj = load_json_object(raw)
        if obj.get("hook_event_name") != "PreToolUse":
            raise ParseError(f"unexpected hook_event_name {obj.get('hook_event_name')!r}")
        tool = req_str(obj, "tool_name")
        session = req_str(obj, "session_id")
        ti = obj.get("tool_input")
        if not isinstance(ti, dict):
            raise ParseError("tool_input is not an object")
        args: dict[str, Any] = dict(ti)
        for k in ("file_path", "notebook_path", "path"):
            if isinstance(ti.get(k), str):
                args.setdefault("path", ti[k])
        cwd = obj.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ParseError("cwd is not a string")
        return build_event(
            source="claude_code",
            session_id=session,
            cwd=cwd,
            tool_name=tool,
            kind=classify(tool),
            args=args,
            agent_id="claude_code",
            raw_ref=obj.get("tool_use_id") if isinstance(obj.get("tool_use_id"), str) else None,
        )

    def respond(self, v: Verdict) -> AdapterResponse:
        """Render a verdict. Deny exits 2; ask uses the documented JSON; allow is silent."""
        if v.action is Action.DENY:
            return AdapterResponse(stderr=reason_text(v), exit_code=2)
        if v.action is Action.ASK:
            out = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": reason_text(v),
                }
            }
            return AdapterResponse(stdout=json.dumps(out), exit_code=0)
        return AdapterResponse(exit_code=0)

    def fail_closed(self, reason: str) -> AdapterResponse:
        """Exit 2 with a non-empty reason."""
        return AdapterResponse(
            stderr=f"sheepdog: {reason or 'failing closed'} (fail closed)", exit_code=2
        )
