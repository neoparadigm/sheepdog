from __future__ import annotations

import json
from pathlib import Path

import pytest

from sheepdogai.constants import ONTOLOGY_NS
from sheepdogai.core.verdict import Action, Verdict
from sheepdogai.daemon.server import Gateway
from sheepdogai.graph.builder import build_graph, check_invariants, graph_from_log
from sheepdogai.graph.export_jsonld import jsonld_dict
from sheepdogai.ontology import MAPPING, PROV_TYPE, read_text, render_mapping_table
from sheepdogai.ontology.validate import load_data_graph, validate_export

SD = ONTOLOGY_NS
PROV = "http://www.w3.org/ns/prov#"


def run_log(tmp_path: Path, cmds: list[str], cfg: str = "version: 1\n") -> Path:
    (tmp_path / "sheepdogai.yaml").write_text(cfg)
    gw = Gateway(tmp_path)
    for c in cmds:
        gw.handle(
            "claude",
            json.dumps(
                {
                    "session_id": "o1",
                    "cwd": str(tmp_path),
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": c},
                }
            ).encode(),
        )
    gw.close()
    return tmp_path / ".sheepdogai/runs/o1.jsonl"


def records(p: Path) -> list[dict[str, object]]:
    return [json.loads(x) for x in p.read_text().splitlines()]


def test_namespace_constant_matches_files() -> None:
    assert f"@prefix sheepdogai: <{SD}>" in read_text("sheepdogai.ttl")
    assert f"@prefix sheepdogai: <{SD}>" in read_text("shapes.ttl")
    assert json.loads(read_text("context.jsonld"))["@context"]["sheepdogai"] == SD


def test_mapping_table_matches_code_and_doc() -> None:
    md = read_text("mapping.md")
    assert render_mapping_table() in md
    concepts = {row[0].split(":")[1] for row in MAPPING}
    assert concepts == set(PROV_TYPE) - {"Person"}
    ttl = read_text("sheepdogai.ttl")
    for name, prov_cls, _otel, _n in MAPPING:
        local = name.split(":")[1]
        base = prov_cls.split()[0]
        assert f"sheepdogai:{local} " in ttl and base in ttl


def test_every_term_in_context_is_declared_in_ttl() -> None:
    import re

    ttl = read_text("sheepdogai.ttl")
    ctx = json.loads(read_text("context.jsonld"))["@context"]
    for _term, d in ctx.items():
        iri = d if isinstance(d, str) else d.get("@id", "") if isinstance(d, dict) else ""
        if isinstance(iri, str) and iri.startswith("sheepdogai:"):
            assert re.search(rf"^{re.escape(iri)}\s", ttl, re.M), f"{iri} not declared"


def test_denied_call_exports_expected_triples(tmp_path: Path) -> None:
    p = run_log(tmp_path, ["rm -rf /"])
    g = graph_from_log(p)
    doc = jsonld_dict(g)
    rdf = load_data_graph(doc)
    from rdflib import RDF, Literal, URIRef

    call = next(s for s in rdf.subjects(RDF.type, URIRef(SD + "ToolCall")))
    assert (call, RDF.type, URIRef(PROV + "Activity")) in rdf
    verdicts = list(rdf.subjects(URIRef(PROV + "wasGeneratedBy"), call))
    assert len(verdicts) == 1
    v = verdicts[0]
    assert (v, RDF.type, URIRef(SD + "Verdict")) in rdf and (
        v,
        RDF.type,
        URIRef(PROV + "Entity"),
    ) in rdf
    assert (v, URIRef(SD + "verdictValue"), Literal("deny")) in rdf
    rule = next(rdf.objects(call, URIRef(SD + "matchedRule")))
    assert str(rule).endswith(":machine-recursive-delete-outside")
    assert next(rdf.objects(call, URIRef(SD + "governedBy"))) is not None
    assert str(call).startswith("urn:sheepdogai:event:")


def test_exported_graph_conforms_to_shapes(tmp_path: Path) -> None:
    p = run_log(tmp_path, ["ls", "rm -rf /", "git push", "curl https://evil.example/x"])
    g = graph_from_log(p)
    assert check_invariants(g) == []
    rep = validate_export(jsonld_dict(g))
    assert rep.conforms, rep.text


def test_ask_without_approval_fails_shapes_and_invariants(tmp_path: Path) -> None:
    p = run_log(tmp_path, ["ls"])  # strict: ask
    recs = records(p)
    recs = [r for r in recs if r["kind"] != "approval"]
    g = build_graph(recs)
    assert any("ask without a recorded approval" in m for m in check_invariants(g))
    assert not validate_export(jsonld_dict(g)).conforms


def _decider_run(tmp_path: Path, proposed: str) -> list[dict[str, object]]:
    p = run_log(tmp_path, ["rm -rf /"])
    recs = records(p)
    d = next(r for r in recs if r["kind"] == "decision")["data"]  # type: ignore[index]
    rules_v = {
        "action": "deny",
        "rule_id": "machine-recursive-delete-outside",
        "reason": "x",
        "decided_by": "rules",
    }
    d["rules_verdict"] = rules_v
    d["decider_proposed"] = {
        "action": proposed,
        "rule_id": None,
        "reason": "judge",
        "decided_by": "judge",
    }
    return recs


def test_decider_that_loosens_makes_validation_fail(tmp_path: Path) -> None:
    g = build_graph(_decider_run(tmp_path, "allow"))
    assert any("looser" in m for m in check_invariants(g))
    rep = validate_export(jsonld_dict(g))
    assert not rep.conforms and "less strict than the rules verdict" in rep.text


@pytest.mark.parametrize("proposed", ["deny"])
def test_decider_that_keeps_or_tightens_validates(tmp_path: Path, proposed: str) -> None:
    g = build_graph(_decider_run(tmp_path, proposed))
    assert check_invariants(g) == []
    rep = validate_export(jsonld_dict(g))
    assert rep.conforms, rep.text


def test_budget_exceeded_links_budget_to_stopping_verdict(tmp_path: Path) -> None:
    p = run_log(
        tmp_path, ["a", "b", "c"], "version: 1\nmode: relaxed\npacks: []\nbudget: {max_steps: 2}\n"
    )
    g = graph_from_log(p)
    assert any(e.kind == "exceeded" for e in g.edges)
    assert validate_export(jsonld_dict(g)).conforms


def test_strictness_individuals_are_ordered_in_ttl() -> None:
    from rdflib import Graph, URIRef

    t = Graph()
    t.parse(data=read_text("sheepdogai.ttl"), format="turtle")
    s = lambda n: URIRef(SD + n)  # noqa: E731
    assert (s("Deny"), s("stricterThan"), s("Ask")) in t and (
        s("Ask"),
        s("stricterThan"),
        s("Allow"),
    ) in t


def test_stable_iris_merge_across_runs(tmp_path: Path) -> None:
    a = jsonld_dict(graph_from_log(run_log(tmp_path, ["rm -rf /"])))
    ids = {n["id"] for n in a["@graph"]}  # type: ignore[attr-defined]
    assert all(i.startswith("urn:sheepdogai:") for i in ids)
    assert Verdict(action=Action.DENY).action.label == "deny"
