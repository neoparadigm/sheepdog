from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sheepdogai.cli.main import main
from sheepdogai.core.errors import SheepdogError
from sheepdogai.graph import only_denied
from sheepdogai.graph.builder import build_graph, check_invariants, graph_from_log
from sheepdogai.graph.export_json import export_json
from sheepdogai.graph.export_jsonld import export_jsonld
from sheepdogai.graph.export_mermaid import export_mermaid

GOLD = Path(__file__).resolve().parent.parent / "replay" / "golden"
LOG = GOLD / "run.jsonl"
FORMATS = {
    "mermaid": ("run.mmd", export_mermaid),
    "json": ("run.json", export_json),
    "jsonld": ("run.jsonld", export_jsonld),
}


@pytest.mark.parametrize("fmt", FORMATS)
def test_golden_files(fmt: str) -> None:
    name, fn = FORMATS[fmt]
    got = fn(graph_from_log(LOG))
    assert got == (GOLD / name).read_text(), f"{name} differs; run tools/make_golden.py if intended"


@pytest.mark.parametrize("fmt", FORMATS)
def test_same_log_same_bytes_across_processes(fmt: str) -> None:
    code = (
        "import sys; sys.path.insert(0,'src');"
        "from pathlib import Path;"
        "from sheepdogai.graph.builder import graph_from_log;"
        "from sheepdogai.graph.export_json import export_json;"
        "from sheepdogai.graph.export_jsonld import export_jsonld;"
        "from sheepdogai.graph.export_mermaid import export_mermaid;"
        f"g=graph_from_log(Path({str(LOG)!r}));"
        f"sys.stdout.write({{'mermaid':export_mermaid,'json':export_json,'jsonld':export_jsonld}}[{fmt!r}](g))"
    )
    env = {**os.environ, "PYTHONHASHSEED": "random"}
    root = Path(__file__).resolve().parents[2]
    outs = {
        subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env=env,
            cwd=root,
            check=True,
        ).stdout
        for _ in range(3)
    }
    assert len(outs) == 1 and outs.pop() == FORMATS[fmt][1](graph_from_log(LOG))


def test_invariants_on_golden() -> None:
    g = graph_from_log(LOG)
    assert check_invariants(g) == []
    calls = [n for n in g.nodes.values() if n.kind == "ToolCall"]
    assert len(calls) == 10
    for c in calls:
        assert len(g.out(c.id, "produced")) == 1
    asks = [c for c in calls if g.nodes[g.out(c.id, "produced")[0]].a("verdict") == "ask"]
    assert asks and all(len(g.out(c.id, "approvedBy")) == 1 for c in asks)


def test_every_log_link_verifies_and_chain_is_in_graph() -> None:
    g = graph_from_log(LOG)
    recs = [json.loads(x) for x in LOG.read_text().splitlines()]
    follows = {(e.src, e.dst) for e in g.edges if e.kind == "follows"}
    assert len(follows) == len(recs) - 1
    for r in recs[1:]:
        assert (
            f"urn:sheepdogai:log:golden:{r['index']}",
            f"urn:sheepdogai:log:golden:{r['index'] - 1}",
        ) in follows


def test_tampered_log_is_refused(tmp_path: Path) -> None:
    p = tmp_path / "x.jsonl"
    p.write_bytes(LOG.read_bytes().replace(b"echo hello", b"echo hellO"))
    with pytest.raises(SheepdogError):
        graph_from_log(p)


def test_only_denied_filter() -> None:
    g = only_denied(graph_from_log(LOG))
    verdicts = [n for n in g.nodes.values() if n.kind == "Verdict"]
    assert verdicts and all(v.a("verdict") == "deny" for v in verdicts)
    assert all(n.a("verdict") != "ask" for n in g.nodes.values() if n.kind == "Verdict")
    assert not any(n.kind == "HumanApproval" for n in g.nodes.values())
    assert "echo hello" not in export_mermaid(g) and "rm -rf /" in export_mermaid(g)


def test_missing_verdict_and_approval_are_flagged() -> None:
    recs = [json.loads(x) for x in LOG.read_text().splitlines()]
    no_approval = [r for r in recs if r["kind"] != "approval"]
    assert any("ask without" in m for m in check_invariants(build_graph(no_approval)))
    g = build_graph(recs)
    edge = next(e for e in g.edges if e.kind == "produced")
    g.edges.discard(edge)
    assert any("0 verdicts" in m for m in check_invariants(g))


def test_cli_graph_command(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    for fmt, (name, _) in FORMATS.items():
        assert main(["graph", str(LOG), "--format", fmt]) == 0
        assert capsys.readouterr().out == (GOLD / name).read_text()
    assert main(["graph", str(LOG), "--format", "mermaid", "--only-denied"]) == 0
    assert "allow-echo" not in capsys.readouterr().out


def test_mermaid_escapes_hostile_labels() -> None:
    recs = [json.loads(x) for x in LOG.read_text().splitlines()]
    evil = 'x"] --> evil["<script>alert(1)</script>|`'
    for r in recs:
        if r["kind"] == "decision" and r["data"]["event"]["seq"] == 1:
            r["data"]["event"]["args"]["command"] = evil
    out = export_mermaid(build_graph(recs))
    assert "<script" not in out and "evil[" not in out
    for line in out.splitlines():
        if line.startswith("  n") and '"' in line:
            label = line.split('"')[1]
            assert not any(ch in label for ch in '"[]{}()|`')
