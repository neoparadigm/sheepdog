"""Scripted agent: replays a YAML list of tool calls. No model, no network.

Payloads are built in each CLI's hook format from the adapter fixtures, so a scripted call goes
through exactly the same adapter code path as a real hook call.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

FIXTURE_BASE = {"claude": "bash_npm_test", "gemini": "shell", "codex": "bash"}


@dataclass(frozen=True)
class Step:
    """One generic tool call: tool is bash|write|read|fetch|mcp|patch."""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    role: str = "benign"  # benign | setup | harm


def _template(cli: str) -> dict[str, Any]:
    f = resources.files("sheepdogai.adapters._fixtures").joinpath(cli, f"{FIXTURE_BASE[cli]}.json")
    data: dict[str, Any] = json.loads(f.read_text("utf-8"))
    return data


def payload_for(cli: str, step: Step, session_id: str, cwd: str) -> bytes:
    """Build the raw hook payload for ``step`` in ``cli``'s format."""
    p = copy.deepcopy(_template(cli))
    p["session_id"], p["cwd"] = session_id, cwd
    a = step.args
    path = a.get("path", "")
    if cli == "claude":
        mapping: dict[str, tuple[str, dict[str, Any]]] = {
            "bash": ("Bash", {"command": a.get("command", "")}),
            "write": ("Write", {"file_path": path, "content": a.get("content", "x")}),
            "read": ("Read", {"file_path": path}),
            "fetch": ("WebFetch", {"url": a.get("url", ""), "prompt": "summarise"}),
            "patch": ("Edit", {"file_path": path, "old_string": "a", "new_string": "b"}),
            "mcp": (
                f"mcp__{a.get('server', 'srv')}__{a.get('name', 'tool')}",
                dict(a.get("args", {})),
            ),
        }
    elif cli == "gemini":
        mapping = {
            "bash": ("run_shell_command", {"command": a.get("command", "")}),
            "write": ("write_file", {"file_path": path, "content": a.get("content", "x")}),
            "read": ("read_file", {"file_path": path}),
            "fetch": ("web_fetch", {"prompt": f"summarise {a.get('url', '')}"}),
            "patch": ("replace", {"file_path": path, "old_string": "a", "new_string": "b"}),
            "mcp": (
                f"mcp_{a.get('server', 'srv')}_{a.get('name', 'tool')}",
                dict(a.get("args", {})),
            ),
        }
        p["hook_event_name"] = "BeforeTool"
    else:  # codex (experimental)
        patch = f"*** Begin Patch\n*** Update File: {path}\n@@\n-a\n+b\n*** End Patch"
        mapping = {
            "bash": ("Bash", {"command": a.get("command", "")}),
            "write": ("apply_patch", {"command": patch}),
            "read": ("Bash", {"command": f"cat {path}"}),
            "fetch": ("mcp__browser__fetch", {"url": a.get("url", "")}),
            "patch": ("apply_patch", {"command": patch}),
            "mcp": (
                f"mcp__{a.get('server', 'srv')}__{a.get('name', 'tool')}",
                dict(a.get("args", {})),
            ),
        }
    name, tool_input = mapping[step.tool]
    p["tool_name"], p["tool_input"] = name, tool_input
    return json.dumps(p).encode()


def load_script(path: Path) -> list[Step]:
    """Load a YAML list of ``{tool: ..., <args>}`` mappings."""
    data = yaml.safe_load(path.read_text("utf-8"))
    return [Step(d["tool"], {k: v for k, v in d.items() if k != "tool"}) for d in data]


class BenignAgent:
    """Yields the steps of a script; the harness decides what to do with each verdict."""

    def __init__(self, steps: list[Step]) -> None:
        self.steps = steps

    def __iter__(self) -> Any:
        return iter(self.steps)
