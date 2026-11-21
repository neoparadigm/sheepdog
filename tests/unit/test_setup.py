from __future__ import annotations

import json
from pathlib import Path

import pytest

from sheepdogai.cli import setup as su
from sheepdogai.cli.main import main
from sheepdogai.daemon.server import Gateway


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")  # no agent CLIs on PATH
    return h


def test_nothing_found(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["setup", "--yes"]) == 1
    assert "No supported agent CLI" in capsys.readouterr().out
    assert not (home / ".claude").exists()


def test_detects_by_config_dir(home: Path) -> None:
    (home / ".claude").mkdir()
    (home / ".gemini").mkdir()
    assert su.detect(home) == ["claude", "gemini"]


def test_non_interactive_needs_yes_and_changes_nothing(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (home / ".claude").mkdir()
    assert main(["setup"]) == 1
    out = capsys.readouterr()
    assert (
        "pass --yes" in out.err
        and "This will change" in out.out
        and "sheepdog hook claude" in out.out
    )
    assert (
        not (home / ".claude" / "settings.json").exists() and not su.user_config_path(home).exists()
    )


def test_setup_applies_selftests_is_idempotent_and_undoes(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (home / ".claude").mkdir()
    (home / ".gemini").mkdir()
    orig = '{"model": "x"}\n'
    (home / ".claude" / "settings.json").write_text(orig)
    assert main(["setup", "--yes", "--mode", "balanced"]) == 0
    out = capsys.readouterr().out
    assert "blocked `rm -rf /` as expected" in out
    assert "sheepdog hook claude" in (home / ".claude/settings.json").read_text()
    assert "sheepdog hook gemini" in (home / ".gemini/settings.json").read_text()
    cfg = su.user_config_path(home)
    assert "mode: balanced" in cfg.read_text() and cfg.stat().st_mode & 0o077 == 0
    assert main(["setup", "--yes"]) == 0 and "already set up" in capsys.readouterr().out
    assert main(["setup", "--undo"]) == 0
    assert (home / ".claude/settings.json").read_text() == orig
    assert not (home / ".gemini/settings.json").exists()
    assert cfg.exists()  # the user's policy is kept


def test_user_wide_policy_applies_in_projects_without_their_own(home: Path, tmp_path: Path) -> None:
    cfg = su.user_config_path(home)
    cfg.parent.mkdir(parents=True)
    cfg.write_text("version: 1\nmode: relaxed\npacks: [self_protect, machine]\n")
    proj = tmp_path / "proj"
    proj.mkdir()
    gw = Gateway(proj)

    def call(cmd: str) -> int:
        return gw.handle(
            "claude",
            json.dumps(
                {
                    "session_id": "u",
                    "cwd": str(proj),
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": cmd},
                }
            ).encode(),
        ).exit_code

    assert call("echo hi") == 0 and call("rm -rf /") == 2
    (proj / "sheepdog.yaml").write_text(
        "version: 1\nmode: relaxed\npacks: []\n"
    )  # project policy wins
    assert call("rm -rf /") == 0  # packs: [] in the project file replaces the user-wide packs
    assert gw.rules_path == proj / "sheepdog.yaml"
    gw.close()
