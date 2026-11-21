"""Codex CLI adapter: PreToolUse hook.  EXPERIMENTAL; parts are UNVERIFIED.

Verified from the Codex source (checked 2026-11-21):
* https://github.com/openai/codex/blob/main/codex-rs/hooks/schema/generated/pre-tool-use.command.input.schema.json
  (input: ``cwd``, ``hook_event_name`` "PreToolUse", ``model``, ``permission_mode``,
  ``session_id``, ``tool_input``, ``tool_name``, ``tool_use_id``, ``transcript_path``, ``turn_id``)
* https://github.com/openai/codex/blob/main/codex-rs/hooks/src/events/pre_tool_use.rs
  (exit 2 with non-empty stderr blocks; exit 0 with ``hookSpecificOutput.permissionDecision``
  "deny" blocks; ``ask`` and ``allow`` are reported as "unsupported permissionDecision" and the
  call proceeds; any other exit code is a failed hook and the call proceeds.)

Consequences: ``can_ask`` is False, deny is exit 2 with a non-empty stderr (an empty stderr
would be treated as a failed hook, i.e. fail open), and every failure path exits 2.

UNVERIFIED: the ``tool_input`` shape of ``apply_patch`` (handled as a string under
``command``/``input``/``patch``), the MCP tool naming (assumed ``mcp__<server>__<tool>``), the
hooks.json/config.toml layout written by ``sheepdog install codex``, and the developers.openai.com
documentation, which was not reachable when this adapter was written.
"""

from __future__ import annotations

from typing import Any

from sheepdogai.adapters import build_event, load_json_object, req_str
from sheepdogai.core.adapter import AdapterCapabilities, AdapterResponse
from sheepdogai.core.errors import ParseError
from sheepdogai.core.events import ToolCallEvent, ToolKind
from sheepdogai.core.verdict import Action, Verdict

SHELLISH = {"Bash", "shell", "local_shell", "exec_command", "container.exec"}


def classify(name: str) -> ToolKind:
    """Map a Codex tool name to a normalised kind (UNVERIFIED for names other than Bash)."""
    if name in SHELLISH:
        return "shell"
    if name == "apply_patch":
        return "file_write"
    if name.startswith("mcp__") or name.startswith("mcp_"):
        return "mcp"
    return "other"


class CodexAdapter:
    """Experimental adapter for Codex CLI's PreToolUse hook."""

    name = "codex"
    experimental = True
    capabilities = AdapterCapabilities(
        can_block=True, can_ask=False, sees_mcp=True, sees_file_edits=True
    )

    def parse(self, raw: bytes) -> ToolCallEvent:
        """Parse a PreToolUse payload."""
        obj = load_json_object(raw)
        if obj.get("hook_event_name") != "PreToolUse":
            raise ParseError(f"unexpected hook_event_name {obj.get('hook_event_name')!r}")
        tool = req_str(obj, "tool_name")
        session = req_str(obj, "session_id")
        ti: Any = obj.get("tool_input")
        if isinstance(ti, str):
            ti = {"command": ti}
        if not isinstance(ti, dict):
            raise ParseError("tool_input is neither object nor string")
        args: dict[str, Any] = dict(ti)
        if tool == "apply_patch":
            for k in ("input", "patch", "command"):
                if isinstance(ti.get(k), str):
                    args["patch"] = ti[k]
                    break
        cwd = obj.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ParseError("cwd is not a string")
        return build_event(
            source="codex",
            session_id=session,
            cwd=cwd,
            tool_name=tool,
            kind=classify(tool),
            args=args,
            agent_id="codex",
        )

    def respond(self, v: Verdict) -> AdapterResponse:
        """Deny/ask exit 2 with a non-empty stderr; allow is silent."""
        if v.action in (Action.DENY, Action.ASK):
            rid = f" [{v.rule_id}]" if v.rule_id else ""
            return AdapterResponse(stderr=f"sheepdog: {v.reason or 'denied'}{rid}", exit_code=2)
        return AdapterResponse(exit_code=0)

    def fail_closed(self, reason: str) -> AdapterResponse:
        """Exit 2 with a non-empty reason."""
        return AdapterResponse(
            stderr=f"sheepdog: {reason or 'failing closed'} (fail closed)", exit_code=2
        )
