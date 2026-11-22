"""sheepdogai's own MCP server (stdio). READ-ONLY by design.

It lets an agent (or you, talking to the agent) ask sheepdogai questions in plain language:
is it working, what was blocked and why, would this command be allowed, is the log intact.
It exposes NO tool that changes rules, mode or hooks: a tool that could loosen the guard would
let the agent loosen its own guard (invariant: self-protection). Tuning stays in the CLI and
behind a human question.

Framing: newline-delimited JSON-RPC 2.0 over stdio (MCP 2025-06-18 transports).
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

from sheepdogai.constants import CLI_NAME, __version__

PROTOCOL = "2025-06-18"
MAX_COMMAND_CHARS = 20_000

TOOLS: list[dict[str, Any]] = [
    {
        "name": "sheepdogai_status",
        "description": "Is sheepdogai working? Plain-language health check (hooks, rules, daemon).",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "sheepdogai_recent",
        "description": "What was recently blocked, asked about or allowed in this project, and why.",
        "inputSchema": {
            "type": "object",
            "properties": {"count": {"type": "integer", "minimum": 1, "maximum": 100}},
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "sheepdogai_check",
        "description": (
            "Dry run: would this shell command be allowed, questioned or blocked, and by which "
            "rule? Nothing is executed or logged."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "sheepdogai_verify_log",
        "description": "Check that a run's tamper-evident log has not been edited (run id only).",
        "inputSchema": {
            "type": "object",
            "properties": {"run": {"type": "string"}},
            "required": ["run"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
]


def _captured(fn: Callable[[], int]) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn()
    return buf.getvalue().strip() or "(no output)"


def _check(project: Path, home: Path, command: str) -> str:
    from sheepdogai.adapters.claude_code import ClaudeCodeAdapter
    from sheepdogai.core.verdict import BudgetState
    from sheepdogai.policy.engine import PolicyEngine
    from sheepdogai.policy.loader import find_rules, load_policy

    if len(command) > MAX_COMMAND_CHARS:
        return "command too long to check"
    payload = {
        "session_id": "dry-run",
        "cwd": str(project),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    ev = ClaudeCodeAdapter().parse(json.dumps(payload).encode())
    policy = load_policy(find_rules(project), project_root=project)
    out = PolicyEngine(policy).decide(ev, BudgetState(), ClaudeCodeAdapter.capabilities)
    v = out.verdict
    word = {"allow": "ALLOWED", "ask": "WOULD ASK YOU", "deny": "BLOCKED"}[v.action.label]
    return f"{word}: {v.reason or 'allowed by default'} [{v.rule_id}]"


def call_tool(name: str, args: dict[str, Any], project: Path, home: Path) -> str:
    """Run one read-only tool and return plain text. Raises ValueError on bad input."""
    if name == "sheepdogai_status":
        from sheepdogai.cli.doctor import cmd_doctor

        return _captured(lambda: cmd_doctor(project, home))
    if name == "sheepdogai_recent":
        from sheepdogai.cli.doctor import cmd_recent

        n = args.get("count", 15)
        if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= 100:
            raise ValueError("count must be an integer from 1 to 100")
        return _captured(lambda: cmd_recent(project, n))
    if name == "sheepdogai_check":
        c = args.get("command")
        if not isinstance(c, str) or not c.strip():
            raise ValueError("command must be a non-empty string")
        return _check(project, home, c)
    if name == "sheepdogai_verify_log":
        from sheepdogai.cli.verify_log import cmd_verify

        r = args.get("run")
        if not isinstance(r, str) or not r or "/" in r or "\\" in r or ".." in r:
            raise ValueError("run must be a run id (no paths)")
        return _captured(lambda: cmd_verify(r, project))
    raise ValueError(f"unknown tool {name!r}")


def handle(msg: dict[str, Any], project: Path, home: Path) -> dict[str, Any] | None:
    """Answer one JSON-RPC message; None for notifications."""
    mid, method = msg.get("id"), msg.get("method")
    if mid is None:
        return None

    def ok(result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def err(code: int, text: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": text}}

    if method == "initialize":
        return ok(
            {
                "protocolVersion": PROTOCOL,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": CLI_NAME, "version": __version__},
                "instructions": "Read-only questions about the sheepdogai safety guard.",
            }
        )
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        p = msg.get("params")
        if not isinstance(p, dict) or not isinstance(p.get("name"), str):
            return err(-32602, "invalid params")
        a = p.get("arguments") or {}
        if not isinstance(a, dict):
            return err(-32602, "arguments must be an object")
        try:
            text, bad = call_tool(p["name"], a, project, home), False
        except ValueError as e:
            text, bad = str(e), True
        except Exception as e:  # never crash the stream; say so plainly
            text, bad = f"sheepdogai could not answer: {type(e).__name__}: {e}", True
        return ok({"content": [{"type": "text", "text": text}], "isError": bad})
    return err(-32601, f"method not found: {method}")


def serve(
    project: Path, home: Path, stdin: IO[str] | None = None, stdout: IO[str] | None = None
) -> int:
    """Read newline-delimited JSON-RPC from stdin until EOF."""
    fin, fout = stdin or sys.stdin, stdout or sys.stdout
    for line in fin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            resp = handle(msg, project, home) if isinstance(msg, dict) else None
        except ValueError:
            resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "parse error"},
            }
        if resp is not None:
            fout.write(json.dumps(resp, separators=(",", ":")) + "\n")
            fout.flush()
    return 0
