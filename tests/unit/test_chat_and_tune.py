from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
import yaml
from tests.helpers import event

from sheepdogai.cli import skills as sk
from sheepdogai.cli.main import main
from sheepdogai.cli.setup import user_config_path
from sheepdogai.cli.tune import add_rule, set_mode
from sheepdogai.core.errors import SheepdogError
from sheepdogai.core.verdict import Action
from sheepdogai.policy.engine import PolicyEngine
from sheepdogai.policy.loader import load_policy


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    return h


def verdict(cfg: Path, project: Path, cmd: str) -> Action:
    return (
        PolicyEngine(load_policy(cfg, project_root=project))
        .decide(event(cmd, cwd=str(project)))
        .verdict.action
    )


def test_mode_edit_keeps_comments_and_validates(tmp_path: Path, home: Path) -> None:
    f = tmp_path / "sheepdogai.yaml"
    f.write_text("# my note\nversion: 1\nmode: strict   # careful\npacks: [machine]\n")
    assert "balanced" in set_mode(tmp_path, home, "balanced")
    assert f.read_text() == "# my note\nversion: 1\nmode: balanced\npacks: [machine]\n"
    f.write_text("version: 1\n")
    set_mode(tmp_path, home, "relaxed")
    assert yaml.safe_load(f.read_text())["mode"] == "relaxed"


def test_allow_and_block_add_valid_rules_in_any_layout(tmp_path: Path, home: Path) -> None:
    for layout in (
        "version: 1\nmode: strict\n",
        "version: 1\nrules: []\nmode: strict\n",
        "version: 1\nrules:\n  - id: a\n    match: {tool: Bash, command: 'x*'}\n    action: ask\nmode: strict\n",
        "version: 1\nmode: strict\nrules:\n  - id: a\n    match: {tool: Bash, command: 'x*'}\n    action: ask\n# end\n",
    ):
        f = tmp_path / "sheepdogai.yaml"
        f.write_text(layout)
        add_rule(tmp_path, home, "npm test*", "allow")
        add_rule(tmp_path, home, "npm publish*", "deny")
        ids = [r["id"] for r in yaml.safe_load(f.read_text())["rules"]]
        assert (
            "user-allow-1" in ids
            and "user-deny-1" in ids
            and yaml.safe_load(f.read_text())["mode"] == "strict"
        )
        assert verdict(f, tmp_path, "npm test --watch") is Action.ALLOW
        assert verdict(f, tmp_path, "npm publish") is Action.DENY


def test_bad_or_overbroad_rules_are_refused_and_file_unchanged(tmp_path: Path, home: Path) -> None:
    f = tmp_path / "sheepdogai.yaml"
    f.write_text(
        "version: 1\nrules:\n  - id: a\n    match: {tool: [Bash, run_shell_command]}\n    action: ask\n"
    )
    before = f.read_text()
    for pat in ("*", "  ", "* *", "?"):
        with pytest.raises(SheepdogError, match="matches everything"):
            add_rule(tmp_path, home, pat, "allow")
    with pytest.raises(SheepdogError, match="unreachable"):  # shadowed by the broader earlier rule
        add_rule(tmp_path, home, "ls*", "allow")
    assert f.read_text() == before


def test_falls_back_to_user_wide_config(tmp_path: Path, home: Path) -> None:
    out = set_mode(tmp_path / "proj", home, "strict")
    assert (
        str(user_config_path(home)) in out and "mode: strict" in user_config_path(home).read_text()
    )


def test_cli_and_bare_invocation(
    tmp_path: Path, home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = ["--project", str(tmp_path)]
    assert main([*base, "mode", "strict"]) == 0 and "Mode is now strict" in capsys.readouterr().out
    assert main([*base, "allow", "make test"]) == 0 and "user-allow-1" in capsys.readouterr().out
    assert main([*base]) in (0, 1)  # bare `sheepdogai` runs the health check
    assert "[" in capsys.readouterr().out


def test_skill_formats_are_valid(home: Path) -> None:
    claude = sk.CLAUDE_SKILL
    fm = yaml.safe_load(claude.split("---")[1])
    assert (
        fm["name"] == "sheepdogai"
        and yaml.safe_load(sk.claude_skill("sheepdog").split("---")[1])["name"] == "sheepdog"
        and "description" in fm
        and "$ARGUMENTS" in claude
    )
    g = tomllib.loads(sk.GEMINI_COMMAND)
    assert (
        set(g) == {"description", "prompt"}
        and "{{args}}" in g["prompt"]
        and "$ARGUMENTS" not in g["prompt"]
    )
    for must in (
        "sheepdogai doctor",
        "sheepdogai recent",
        "sheepdogai mode",
        "sheepdogai allow",
        "workaround",
    ):
        assert must in claude


def test_skill_install_does_not_clobber_and_remove_only_ours(home: Path) -> None:
    done = sk.install_skill("claude", home)
    assert {p.parent.name for p in done} == {
        "sheepdogai",
        "sheepdog",
    }  # /sheepdogai and the short /sheepdog
    assert sk.remove_skill("claude", home) and not any(p.exists() for p in done)
    alias = home / ".claude/skills/sheepdog/SKILL.md"
    alias.parent.mkdir(parents=True, exist_ok=True)
    alias.write_text("someone else's /sheepdog skill")
    done = sk.install_skill("claude", home)
    assert [p.parent.name for p in done] == [
        "sheepdogai"
    ] and alias.read_text() == "someone else's /sheepdog skill"
    assert sk.remove_skill("claude", home) and alias.exists()  # only ours is removed
    assert sk.install_skill("codex", home) == []


def test_setup_installs_chat_command_and_undo_removes_it(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (home / ".claude").mkdir()
    (home / ".gemini").mkdir()
    assert main(["setup", "--yes"]) == 0
    out = capsys.readouterr().out
    assert "type /sheepdog" in out
    for n in ("sheepdog", "sheepdogai"):
        assert (home / f".claude/skills/{n}/SKILL.md").exists() and (
            home / f".gemini/commands/{n}.toml"
        ).exists()
    assert main(["setup", "--undo"]) == 0
    assert (
        not (home / ".claude/skills/sheepdog").exists()
        and not (home / ".gemini/commands/sheepdogai.toml").exists()
    )


def test_agent_cannot_loosen_or_reinstall_unattended(tmp_path: Path) -> None:
    from tests.helpers import make_engine

    eng = make_engine(tmp_path, mode="relaxed", packs=[])
    for cmd in ("sheepdogai mode relaxed", "sheepdogai allow 'rm *'", "sheepdogai block 'x*'"):
        assert eng.decide(event(cmd, cwd=str(tmp_path))).verdict.action is Action.ASK, cmd
    for cmd in ("sheepdogai setup --yes", "sheepdogai setup --undo", "sheepdogai uninstall claude"):
        v = eng.decide(event(cmd, cwd=str(tmp_path))).verdict
        assert v.action is Action.DENY, cmd
    for cmd in ("sheepdogai doctor", "sheepdogai recent -n 5", "sheepdogai status"):
        assert eng.decide(event(cmd, cwd=str(tmp_path))).verdict.action is Action.ALLOW, cmd


def test_replay_and_status_use_the_user_wide_policy(
    home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    from sheepdogai.daemon.server import Gateway

    cfg = user_config_path(home)
    cfg.parent.mkdir(parents=True)
    cfg.write_text(
        "version: 1\nmode: relaxed\npacks: [self_protect, machine]\n"
    )  # differs from the strict defaults
    proj = tmp_path / "proj"
    proj.mkdir()
    gw = Gateway(proj)
    for c in ("echo hi", "rm -rf /", "ls"):
        gw.handle(
            "claude",
            json.dumps(
                {
                    "session_id": "r",
                    "cwd": str(proj),
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": c},
                }
            ).encode(),
        )
    gw.close()
    assert (
        main(["--project", str(proj), "replay", "r"]) == 0
    )  # no false diffs against strict defaults
    assert "0 verdict(s) differ" in capsys.readouterr().out
    assert main(["--project", str(proj), "status"]) == 0
    assert str(cfg) in capsys.readouterr().out


def test_reason_for_rules_added_by_allow_and_block_is_human(tmp_path: Path, home: Path) -> None:
    f = tmp_path / "sheepdogai.yaml"
    f.write_text("version: 1\nmode: relaxed\npacks: []\n")
    add_rule(tmp_path, home, "npm publish*", "deny")
    d = PolicyEngine(load_policy(f, project_root=tmp_path)).decide(
        event("npm publish", cwd=str(tmp_path))
    )
    assert d.verdict.reason == "you chose to block commands matching npm publish*"
