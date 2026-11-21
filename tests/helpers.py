"""Shared test helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sheepdogai.core.canonical import uuid7
from sheepdogai.core.events import Provenance, ToolCallEvent, ToolKind, ToolRef
from sheepdogai.policy.engine import PolicyEngine
from sheepdogai.policy.loader import build_policy
from sheepdogai.policy.schema import Config


def event(
    command: str | None = None,
    *,
    kind: ToolKind = "shell",
    name: str | None = None,
    cwd: str | None = None,
    untrusted: bool = False,
    seq: int = 1,
    **args: Any,
) -> ToolCallEvent:
    a: dict[str, Any] = dict(args)
    if command is not None:
        a["command"] = command
    return ToolCallEvent(
        event_id=uuid7(),
        run_id="run",
        session_id="s",
        seq=seq,
        ts=datetime.now(UTC),
        source="scripted",
        agent_id="agent",
        tool=ToolRef(
            name=name
            or {
                "shell": "Bash",
                "file_write": "Write",
                "file_read": "Read",
                "network": "WebFetch",
            }.get(kind, "tool"),
            kind=kind,
        ),
        args=a,
        cwd=cwd,
        provenance=Provenance(untrusted_content_seen=untrusted, trusted=not untrusted),
    )


def make_engine(project: Path, home: Path | None = None, **cfg: Any) -> PolicyEngine:
    cfg.setdefault("settings", {"scratch_paths": []})
    config = Config.model_validate({"version": 1, **cfg})
    pol = build_policy(config, project_root=str(project), home=str(home or project.parent / "home"))
    return PolicyEngine(pol)


def event_raw(kind: ToolKind, args: dict[str, Any], cwd: str | None) -> ToolCallEvent:
    """Build an event with fully arbitrary args (for property tests)."""
    e = event(None, kind=kind, cwd=cwd)
    return e.model_copy(update={"args": args})
