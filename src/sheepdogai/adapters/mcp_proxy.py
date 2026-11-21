"""MCP proxy adapter. EXPERIMENTAL (it passes the shared conformance suite, but is unproven in the
field and its behaviour with real agents/servers is UNVERIFIED).

A stdio proxy between an agent (MCP client) and any MCP server. It passes ``tools/list`` and every
other message through unchanged, turns each ``tools/call`` into one standard event, asks the same
engine (via the daemon) and either forwards the call or answers the agent with a tool error result
that names the rule. If the daemon cannot answer, the call is refused (fail closed). A tool result
is never rewritten except for secret redaction.

Framing: https://github.com/modelcontextprotocol/modelcontextprotocol (docs/specification/2025-06-18/
basic/transports.mdx, checked 2026-11-21): stdio messages are newline-delimited JSON, with no
embedded newlines. Tool errors: ``result.isError = true`` with text content
(docs/specification/2025-06-18/server/tools.mdx).
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import threading
from collections.abc import Callable
from typing import IO, Any

from sheepdogai.adapters import build_event, load_json_object, req_str
from sheepdogai.core.adapter import AdapterCapabilities, AdapterResponse
from sheepdogai.core.errors import ParseError
from sheepdogai.core.events import ToolCallEvent
from sheepdogai.core.verdict import Action, Verdict
from sheepdogai.redact.secrets import redact_text

Decide = Callable[[bytes], tuple[int, str, str]]


class McpProxyAdapter:
    """Adapter whose payload is ``{session_id, cwd, server, request: <tools/call JSON-RPC>}``."""

    name = "mcp_proxy"
    experimental = True
    capabilities = AdapterCapabilities(
        can_block=True, can_ask=False, sees_mcp=True, sees_file_edits=False
    )

    def parse(self, raw: bytes) -> ToolCallEvent:
        """Parse a wrapped ``tools/call`` request."""
        obj = load_json_object(raw)
        req = obj.get("request")
        if not isinstance(req, dict) or req.get("method") != "tools/call":
            raise ParseError("not a tools/call request")
        params = req.get("params")
        if not isinstance(params, dict):
            raise ParseError("tools/call without params")
        tool = req_str(params, "name")
        args = params.get("arguments", {})
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise ParseError("tools/call arguments is not an object")
        server = req_str(obj, "server")
        session = req_str(obj, "session_id")
        cwd = obj.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ParseError("cwd is not a string")
        a: dict[str, Any] = dict(args)
        for k in ("path", "file_path", "url"):
            if isinstance(args.get(k), str):
                a.setdefault(k, args[k])
        return build_event(
            source="framework",
            session_id=session,
            cwd=cwd,
            tool_name=f"mcp__{server}__{tool}",
            kind="mcp",
            args=a,
            agent_id=f"mcp_proxy:{server}",
        )

    def respond(self, v: Verdict) -> AdapterResponse:
        """Deny/ask exit 2 with the rule in stderr (the proxy turns it into an error result)."""
        if v.action in (Action.DENY, Action.ASK):
            rid = f" [{v.rule_id}]" if v.rule_id else ""
            return AdapterResponse(
                stderr=f"sheepdog: blocked{rid}: {v.reason or 'denied'}", exit_code=2
            )
        return AdapterResponse(exit_code=0)

    def fail_closed(self, reason: str) -> AdapterResponse:
        """Exit 2 with a non-empty reason."""
        return AdapterResponse(
            stderr=f"sheepdog: {reason or 'failing closed'} (fail closed)", exit_code=2
        )


def error_result(req_id: Any, text: str) -> bytes:
    """A tool *execution* error result (isError) so the model sees why the call was refused."""
    msg = {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": True},
    }
    return json.dumps(msg, separators=(",", ":")).encode() + b"\n"


def redact_result(line: bytes) -> bytes:
    """Redact secrets in a tool result's text. Returns the original bytes if nothing changed."""
    try:
        msg = json.loads(line)
    except ValueError:
        return line
    res = msg.get("result") if isinstance(msg, dict) else None
    if not isinstance(res, dict):
        return line
    changed = False

    def walk(o: Any) -> Any:
        nonlocal changed
        if isinstance(o, str):
            r = redact_text(o)
            changed |= r != o
            return r
        if isinstance(o, list):
            return [walk(x) for x in o]
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        return o

    for key in ("content", "structuredContent"):
        if key in res:
            res[key] = walk(res[key])
    return json.dumps(msg, separators=(",", ":")).encode() + b"\n" if changed else line


class McpProxy:
    """Bridge agent <-> server. ``decide`` receives the wrapped payload and returns (code, out, err)."""

    def __init__(
        self,
        server_cmd: list[str],
        server_name: str,
        session_id: str,
        cwd: str,
        decide: Decide,
        agent_in: IO[bytes] | None = None,
        agent_out: IO[bytes] | None = None,
    ) -> None:
        self.cmd, self.name, self.session, self.cwd, self.decide = (
            server_cmd,
            server_name,
            session_id,
            cwd,
            decide,
        )
        self.agent_in = agent_in or sys.stdin.buffer
        self.agent_out = agent_out or sys.stdout.buffer
        self._out_lock = threading.Lock()
        self._call_ids: set[str] = set()
        self._ids_lock = threading.Lock()

    def _to_agent(self, data: bytes) -> None:
        with self._out_lock:
            self.agent_out.write(data)
            self.agent_out.flush()

    def _verdict(self, msg: dict[str, Any]) -> str | None:
        """None when allowed, else the refusal text. Never raises."""
        try:
            payload = json.dumps(
                {"session_id": self.session, "cwd": self.cwd, "server": self.name, "request": msg}
            ).encode()
            code, _out, err = self.decide(payload)
        except BaseException as e:  # fail closed
            return f"sheepdog: proxy error {type(e).__name__} (fail closed)"
        return None if code == 0 else (err.strip() or "sheepdog: blocked (fail closed)")

    def _agent_to_server(self, proc: subprocess.Popen[bytes]) -> None:
        assert proc.stdin is not None
        for line in self.agent_in:
            try:
                msg = json.loads(line)
            except ValueError:
                msg = None
            if isinstance(msg, list) and any(
                isinstance(m, dict) and m.get("method") == "tools/call" for m in msg
            ):
                self._to_agent(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {
                                "code": -32600,
                                "message": "sheepdog: batched tools/call is not supported (fail closed)",
                            },
                        }
                    ).encode()
                    + b"\n"
                )
                continue
            if isinstance(msg, dict) and msg.get("method") == "tools/call":
                refusal = self._verdict(msg)
                if refusal is not None:
                    if "id" in msg:
                        self._to_agent(error_result(msg["id"], refusal))
                    continue
                if "id" in msg:
                    with self._ids_lock:
                        self._call_ids.add(json.dumps(msg["id"]))
            try:
                proc.stdin.write(line if line.endswith(b"\n") else line + b"\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError):
                break
        with_suppress_close(proc.stdin)

    def _server_to_agent(self, proc: subprocess.Popen[bytes]) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            out = line
            try:
                msg = json.loads(line)
            except ValueError:
                msg = None
            if isinstance(msg, dict) and "id" in msg and "result" in msg:
                with self._ids_lock:
                    is_call = json.dumps(msg["id"]) in self._call_ids
                    self._call_ids.discard(json.dumps(msg["id"]))
                if is_call:
                    out = redact_result(line)
            self._to_agent(out)

    def run(self) -> int:
        """Spawn the server (argv list, no shell), pump both directions, return its exit code."""
        proc = subprocess.Popen(
            self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None
        )  # noqa: S603
        t1 = threading.Thread(target=self._agent_to_server, args=(proc,), daemon=True)
        t2 = threading.Thread(target=self._server_to_agent, args=(proc,), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        rc = proc.wait()
        t2.join(timeout=5)
        return rc


def with_suppress_close(f: IO[bytes]) -> None:
    """Close a pipe, ignoring errors."""
    with contextlib.suppress(OSError):
        f.close()


def default_decide(payload: bytes) -> tuple[int, str, str]:
    """Ask the local daemon (fail closed if it cannot answer)."""
    from sheepdogai.daemon.client import request

    return request("mcp", payload, experimental=True)
