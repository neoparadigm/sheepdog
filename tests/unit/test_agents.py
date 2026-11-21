from __future__ import annotations

import json
from pathlib import Path

import pytest
from agents.harness_runner import Harness
from agents.scripted import obfuscate
from agents.scripted.attacker_agent import AttackerAgent, AttackScenario
from agents.scripted.benign_agent import BenignAgent, Step, load_script, payload_for

from sheepdogai.adapters import get_adapter


@pytest.mark.parametrize("cli", ["claude", "gemini", "codex"])
@pytest.mark.parametrize("tool", ["bash", "write", "read", "fetch", "patch", "mcp"])
def test_payloads_parse_with_the_real_adapter(cli: str, tool: str) -> None:
    step = Step(
        tool,
        {
            "command": "ls",
            "path": "/p/a.py",
            "url": "https://github.com/x",
            "server": "fs",
            "name": "read_file",
            "args": {"path": "/p/a"},
        },
    )
    raw = payload_for(cli, step, "sess", "/p")
    ev = get_adapter(cli, experimental=True).parse(raw)
    assert ev.session_id == "sess" and ev.cwd == "/p"
    assert json.loads(raw)["session_id"] == "sess"


def test_benign_agent_script_replay(tmp_path: Path) -> None:
    f = tmp_path / "s.yaml"
    f.write_text("- {tool: bash, command: ls}\n- {tool: read, path: /p/x}\n")
    steps = load_script(f)
    assert [s.tool for s in BenignAgent(steps)] == ["bash", "read"]
    h = Harness("claude")
    try:
        res = h.run("benign", steps)
        assert len(res) == 2 and all(r.verdict in {"allow", "ask", "deny"} for r in res)
        assert "flowchart" in h.graph_mermaid("benign")
    finally:
        h.cleanup()


def test_attacker_emits_marker_then_harm_and_variants() -> None:
    sc = AttackScenario(
        "X", [Step("bash", {"command": "rm -rf /"}, "harm")], "https://e.example", ["core"]
    )
    v = AttackerAgent(sc).variants()
    assert v[0][0] == "plain" and v[0][1][0].role == "setup" and v[0][1][-1].role == "harm"
    assert len(v) > 5 and all(s[1][0].role == "setup" for s in v)


def test_every_generator_runs_and_changes_the_string() -> None:
    cmd = "rm -rf /tmp/x"
    applicable = {n: g(cmd) for n, g in obfuscate.ALL.items()}
    assert sum(1 for v in applicable.values() if v) >= 25
    assert all(v != cmd for v in applicable.values() if v)
    assert all(v != "" for _, v in obfuscate.variants(""))
    assert obfuscate.brace("rm -rf 'a b'") is None
