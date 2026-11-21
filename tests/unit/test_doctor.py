from __future__ import annotations

import json
from pathlib import Path

import pytest

from sheepdogai.cli.main import main
from sheepdogai.daemon.server import Gateway


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    return h


def test_doctor_fails_with_fix_hints_before_setup(
    home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (home / ".claude").mkdir()
    assert main(["--project", str(tmp_path), "doctor"]) == 1
    out = capsys.readouterr().out
    assert (
        "protection is switched on" in out
        and "fix: run: sheepdog setup" in out
        and "problem(s) found" in out
    )


def test_doctor_passes_after_setup_and_catches_breakage(
    home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    (home / ".claude").mkdir()
    bin_dir = Path(__file__).resolve().parents[2] / ".venv" / "bin"
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    assert main(["setup", "--yes"]) == 0
    capsys.readouterr()
    proj = tmp_path / "p"
    proj.mkdir()
    assert main(["--project", str(proj), "doctor"]) == 0
    out = capsys.readouterr().out
    assert "[FAIL]" not in out and "Everything looks good" in out and "sudo whoami" in out
    (home / ".config/sheepdog/sheepdog.yaml").write_text("version: 1\nbogus: 1\n")
    assert main(["--project", str(proj), "doctor"]) == 1
    assert "has a mistake" in capsys.readouterr().out


def test_doctor_detects_tampered_log(
    home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    gw = Gateway(tmp_path)
    gw.handle(
        "claude",
        json.dumps(
            {
                "session_id": "s",
                "cwd": str(tmp_path),
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "ls"},
            }
        ).encode(),
    )
    gw.close()
    log = tmp_path / ".sheepdog/runs/s.jsonl"
    log.write_bytes(log.read_bytes().replace(b'"ls"', b'"lz"'))
    main(["--project", str(tmp_path), "doctor"])
    assert "changed or damaged" in capsys.readouterr().out


def test_recent_in_plain_language(
    home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--project", str(tmp_path), "recent"]) == 0
    assert "Nothing recorded" in capsys.readouterr().out
    gw = Gateway(tmp_path)
    for c in ("rm -rf /", "sudo whoami"):
        gw.handle(
            "claude",
            json.dumps(
                {
                    "session_id": "s",
                    "cwd": str(tmp_path),
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": c},
                }
            ).encode(),
        )
    gw.close()
    assert main(["--project", str(tmp_path), "recent"]) == 0
    out = capsys.readouterr().out
    assert "BLOCKED" in out and "rm -rf /" in out and "why:" in out and "sudo whoami" in out
