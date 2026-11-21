"""Invariant 3: an agent event that edits sheepdogai.yaml, the hook config or .sheepdogai/ is never
allowed without a human (verdict ask or deny), in every mode and whatever the user's rules say."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.helpers import event, make_engine

from sheepdogai.core.verdict import Action
from sheepdogai.daemon.server import Gateway

PROTECTED = [
    "sheepdogai.yaml",
    "./sheepdogai.yaml",
    "src/../sheepdogai.yaml",
    "SHEEPDOGAI.YAML",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".gemini/settings.json",
    ".codex/hooks.json",
    ".codex/config.toml",
    ".sheepdogai/shared.yaml",
    ".sheepdogai/runs/r1.jsonl",
    ".sheepdogai/runs/r1.jsonl.head",
    ".sheepdogai/install/x.json",
    ".sheepdogai/approved/abc",
]
SHELL = [
    "echo x > {p}",
    "echo x >> {p}",
    "sed -i s/a/b/ {p}",
    "rm {p}",
    "rm -f {p}",
    "mv {p} /tmp/x",
    "mv x {p}",
    "cp x {p}",
    "tee {p}",
    "truncate -s0 {p}",
    "chmod 777 {p}",
    "ln -sf x {p}",
    "bash -c 'echo x > {p}'",
    "python3 -c \"open('{p}','w')\" {p}",
    "dd if=/dev/zero of={p}",
    "install x {p}",
    "touch {p}",
    "perl -pi -e s/a/b/ {p}",
]
MODES = ["strict", "balanced", "relaxed"]
ALLOW_ALL = [
    {"id": "allow-everything", "match": {"tool": ["Bash", "Write", "Edit"]}, "action": "allow"}
]


def verdict_for(proj: Path, mode: str, e: Any, rules: list[dict[str, Any]] | None = None) -> Action:
    eng = make_engine(proj, mode=mode, packs=[], rules=rules or [])  # self_protect is forced on
    return eng.decide(e).verdict.action


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("path", PROTECTED)
def test_file_tool_edits_never_allowed(tmp_path: Path, mode: str, path: str) -> None:
    for tool in ("Write", "Edit"):
        for rules in (None, ALLOW_ALL):
            e = event(kind="file_write", name=tool, file_path=path, cwd=str(tmp_path))
            assert verdict_for(tmp_path, mode, e, rules) >= Action.ASK, (mode, path, tool)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("tmpl", SHELL)
@pytest.mark.parametrize("path", PROTECTED[:6] + [".sheepdogai/runs/r1.jsonl"])
def test_shell_edits_never_allowed(tmp_path: Path, mode: str, tmpl: str, path: str) -> None:
    for rules in (None, ALLOW_ALL):
        e = event(tmpl.format(p=path), cwd=str(tmp_path))
        assert verdict_for(tmp_path, mode, e, rules) >= Action.ASK, (mode, tmpl, path)


def test_log_dir_is_denied_not_just_asked(tmp_path: Path) -> None:
    e = event("rm -rf .sheepdogai", cwd=str(tmp_path))
    assert verdict_for(tmp_path, "relaxed", e) is Action.DENY


def test_symlink_to_protected_file_is_followed(tmp_path: Path) -> None:
    (tmp_path / "sheepdogai.yaml").write_text("version: 1\n")
    (tmp_path / "innocent.txt").symlink_to(tmp_path / "sheepdogai.yaml")
    e = event(kind="file_write", file_path="innocent.txt", cwd=str(tmp_path))
    assert verdict_for(tmp_path, "relaxed", e) >= Action.ASK
    assert (
        verdict_for(tmp_path, "relaxed", event("echo x > innocent.txt", cwd=str(tmp_path)))
        >= Action.ASK
    )


def test_mcp_and_patch_tools_are_covered(tmp_path: Path) -> None:
    for e in (
        event(kind="mcp", name="mcp__fs__write_file", path="sheepdogai.yaml", cwd=str(tmp_path)),
        event(
            kind="mcp", name="mcp__fs__edit", file_path=".claude/settings.json", cwd=str(tmp_path)
        ),
        event(
            kind="other",
            name="apply_patch",
            patch="*** Update File: sheepdogai.yaml\n",
            cwd=str(tmp_path),
        ),
        event(
            kind="file_write",
            name="apply_patch",
            patch="*** Delete File: .sheepdogai/runs/a\n",
            cwd=str(tmp_path),
        ),
    ):
        assert verdict_for(tmp_path, "relaxed", e) >= Action.ASK, e.tool.name


def test_reads_stay_possible(tmp_path: Path) -> None:
    for e in (
        event("cat sheepdogai.yaml", cwd=str(tmp_path)),
        event(kind="file_read", file_path="sheepdogai.yaml", cwd=str(tmp_path)),
        event("ls .sheepdogai/runs", cwd=str(tmp_path)),
        event("git diff -- sheepdogai.yaml", cwd=str(tmp_path)),
    ):
        assert verdict_for(tmp_path, "relaxed", e) is Action.ALLOW


def test_through_adapters_and_gateway(tmp_path: Path) -> None:
    (tmp_path / "sheepdogai.yaml").write_text("version: 1\nmode: relaxed\npacks: []\n")
    gw = Gateway(tmp_path)
    cases = [
        (
            "claude",
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {"file_path": str(tmp_path / "sheepdogai.yaml"), "content": "x"},
            },
        ),
        (
            "claude",
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf .sheepdogai"},
            },
        ),
        (
            "gemini",
            {
                "hook_event_name": "BeforeTool",
                "tool_name": "write_file",
                "tool_input": {
                    "file_path": str(tmp_path / ".gemini/settings.json"),
                    "content": "{}",
                },
            },
        ),
        (
            "codex",
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "apply_patch",
                "tool_input": {
                    "command": "*** Begin Patch\n*** Update File: sheepdogai.yaml\n*** End Patch"
                },
            },
        ),
    ]
    for cli, p in cases:
        raw = json.dumps({"session_id": "sp", "cwd": str(tmp_path), **p}).encode()
        r = gw.handle(cli, raw, experimental=True)
        blocked = r.exit_code == 2 or '"ask"' in r.stdout
        assert blocked, (cli, p["tool_name"], r)
    gw.close()


def test_user_rules_cannot_precede_self_protect(tmp_path: Path) -> None:
    eng = make_engine(tmp_path, mode="relaxed", rules=ALLOW_ALL)
    assert eng.policy.rules[0].origin == "self_protect"
    d = eng.decide(event(kind="file_write", file_path="sheepdogai.yaml", cwd=str(tmp_path)))
    assert d.origin == "self_protect" and d.verdict.rule_id == "sp-rules-and-hooks"
