"""``wrap(tool)``: guard a plain Python callable used by an agent framework with no hooks or MCP.

EXPERIMENTAL (UNVERIFIED against real frameworks: it has only been exercised by this repository's
tests and the shared adapter conformance suite). Fail closed: if the decision cannot be obtained, or
is anything but allow, the tool is not called and ``ToolBlocked`` is raised.
"""

from __future__ import annotations

import functools
import inspect
import json
import os
from collections.abc import Callable
from typing import Any, TypeVar

from sheepdogai.adapters import build_event, load_json_object, req_str
from sheepdogai.core.adapter import AdapterCapabilities, AdapterResponse
from sheepdogai.core.errors import ParseError, SheepdogError
from sheepdogai.core.events import ToolCallEvent, ToolKind
from sheepdogai.core.verdict import Action, Verdict

F = TypeVar("F", bound=Callable[..., Any])
KINDS = {"shell", "file_read", "file_write", "network", "mcp", "other"}


class ToolBlocked(SheepdogError):
    """Raised instead of calling the tool when the verdict is not allow."""


class FrameworkAdapter:
    """Payload: ``{session_id, cwd, tool_name, kind, arguments, framework?}``."""

    name = "framework"
    experimental = True
    capabilities = AdapterCapabilities(
        can_block=True, can_ask=False, sees_mcp=False, sees_file_edits=False
    )

    def parse(self, raw: bytes) -> ToolCallEvent:
        """Parse a framework tool call."""
        obj = load_json_object(raw)
        tool = req_str(obj, "tool_name")
        session = req_str(obj, "session_id")
        kind = obj.get("kind")
        if kind not in KINDS:
            raise ParseError(f"invalid kind {kind!r}")
        args = obj.get("arguments")
        if not isinstance(args, dict):
            raise ParseError("arguments is not an object")
        cwd = obj.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise ParseError("cwd is not a string")
        a: dict[str, Any] = dict(args)
        for k in ("path", "file_path", "url", "command"):
            if isinstance(args.get(k), str):
                a.setdefault(k, args[k])
        fw = obj.get("framework")
        return build_event(
            source="framework",
            session_id=session,
            cwd=cwd,
            tool_name=tool,
            kind=kind,
            args=a,
            agent_id=f"framework:{fw}" if isinstance(fw, str) else "framework",
        )

    def respond(self, v: Verdict) -> AdapterResponse:
        """Deny/ask exit 2 with the reason; allow is silent."""
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


def wrap(
    tool: F,
    *,
    name: str | None = None,
    kind: ToolKind = "other",
    session_id: str | None = None,
    gateway: Any = None,
    framework: str | None = None,
) -> F:
    """Return ``tool`` guarded by sheepdog. ``gateway`` is an in-process Gateway, else the daemon."""
    tool_name = name or getattr(tool, "__name__", "tool")
    sig = inspect.signature(tool)
    sid = session_id or f"wrap-{os.getpid()}"

    @functools.wraps(tool)
    def guarded(*a: Any, **kw: Any) -> Any:
        try:
            bound = sig.bind(*a, **kw)
            bound.apply_defaults()
            payload = json.dumps(
                {
                    "session_id": sid,
                    "cwd": os.getcwd(),
                    "tool_name": tool_name,
                    "kind": kind,
                    "arguments": bound.arguments,
                    "framework": framework,
                },
                default=str,
            ).encode()
            if gateway is not None:
                r = gateway.handle("framework", payload, experimental=True)
                code, err = r.exit_code, r.stderr
            else:
                from sheepdogai.daemon.client import request

                code, _out, err = request("framework", payload, experimental=True)
        except BaseException as e:  # never call the tool if the decision path failed
            raise ToolBlocked(
                f"sheepdog: could not obtain a decision ({type(e).__name__}); not calling the tool"
            ) from e
        if code != 0:
            raise ToolBlocked(err.strip() or "sheepdog: blocked")
        return tool(*a, **kw)

    return guarded  # type: ignore[return-value]
