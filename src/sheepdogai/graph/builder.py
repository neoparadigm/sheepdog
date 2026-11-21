"""Build a directed run graph from a verified run log. Plain dataclasses, deterministic."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sheepdogai.core.errors import SheepdogError
from sheepdogai.log.verify import verify_log

NODE_KINDS = (
    "Run",
    "Agent",
    "ToolCall",
    "Policy",
    "Rule",
    "Verdict",
    "Decider",
    "Budget",
    "HumanApproval",
    "LogRecord",
    "Adapter",
    "Person",
)
EDGE_KINDS = (
    "issues",
    "governedBy",
    "matchedRule",
    "produced",
    "decidedBy",
    "exceeded",
    "approvedBy",
    "follows",
    "partOf",
    "memberOf",
    "observedBy",
    "priorVerdict",
    "associatedWith",
)
STRICT = {"allow": 0, "ask": 1, "deny": 2}
OUTCOMES_OK = {"approved", "denied", "timeout_deny", "delegated", "allow_once", "allow_run"}

NS = "urn:sheepdogai:"


@dataclass(frozen=True)
class Node:
    """A graph node. ``attrs`` hold only JSON scalars."""

    id: str
    kind: str
    label: str
    attrs: tuple[tuple[str, Any], ...] = ()

    def a(self, key: str, default: Any = None) -> Any:
        """Attribute lookup."""
        for k, v in self.attrs:
            if k == key:
                return v
        return default


@dataclass(frozen=True, order=True)
class Edge:
    """A directed, typed edge."""

    kind: str
    src: str
    dst: str


@dataclass
class Graph:
    """Nodes by id and a set of edges."""

    nodes: dict[str, Node] = field(default_factory=dict)
    edges: set[Edge] = field(default_factory=set)

    def add(self, n: Node) -> None:
        """Add (or keep the first) node with this id."""
        self.nodes.setdefault(n.id, n)

    def link(self, kind: str, src: str, dst: str) -> None:
        """Add an edge."""
        self.edges.add(Edge(kind, src, dst))

    def out(self, src: str, kind: str) -> list[str]:
        """Destinations of ``kind`` edges from ``src``."""
        return sorted(e.dst for e in self.edges if e.src == src and e.kind == kind)

    def sorted_nodes(self) -> list[Node]:
        """Nodes in stable order."""
        return [self.nodes[k] for k in sorted(self.nodes)]

    def sorted_edges(self) -> list[Edge]:
        """Edges in stable order."""
        return sorted(self.edges)


def _node(kind: str, id_: str, label: str, **attrs: Any) -> Node:
    return Node(id_, kind, label, tuple(sorted((k, v) for k, v in attrs.items() if v is not None)))


def _verdict_attrs(v: dict[str, Any]) -> dict[str, Any]:
    val = (
        v["action"] if isinstance(v["action"], str) else ("allow", "ask", "deny")[int(v["action"])]
    )
    return {
        "verdict": val,
        "strictness": STRICT[val],
        "reason": v.get("reason") or None,
        "rule_id": v.get("rule_id"),
    }


def build_graph(records: list[dict[str, Any]]) -> Graph:  # noqa: C901
    """Build the graph from already-verified log records."""
    g = Graph()
    anchor = records[0]["data"]
    run_id, phash = anchor["run_id"], anchor["policy_hash"]
    run = f"{NS}run:{run_id}"
    pol = f"{NS}policy:{phash}"
    g.add(
        _node(
            "Run",
            run,
            f"run {run_id}",
            run_id=run_id,
            policy_hash=phash,
            schema_version=anchor.get("schema_version"),
        )
    )
    g.add(_node("Policy", pol, f"policy {phash[:12]}", policy_hash=phash))
    g.link("partOf", pol, run)
    prev_rec: str | None = None
    approvals = {r["data"]["event_id"]: r["data"] for r in records if r["kind"] == "approval"}
    for r in records:
        lr = f"{NS}log:{run_id}:{r['index']}"
        g.add(
            _node(
                "LogRecord",
                lr,
                f"#{r['index']} {r['kind']}",
                index=r["index"],
                record_kind=r["kind"],
                hash=r["hash"],
                prev_hash=r["prev_hash"],
            )
        )
        g.link("partOf", lr, run)
        if prev_rec:
            g.link("follows", lr, prev_rec)
        prev_rec = lr
        if r["kind"] != "decision":
            continue
        d = r["data"]
        ev = d["event"]
        eid = ev["event_id"]
        call = f"{NS}event:{eid}"
        agent = f"{NS}agent:{ev['agent_id']}"
        adapter_name = d.get("adapter", ev["source"])
        adapter = f"{NS}adapter:{adapter_name}"
        summary = ev["args"].get("command") or ev["args"].get("path") or ev["args"].get("url") or ""
        g.add(
            _node(
                "ToolCall",
                call,
                f"{ev['tool']['name']} #{ev['seq']}",
                seq=ev["seq"],
                ts=ev["ts"],
                tool_name=ev["tool"]["name"],
                tool_kind=ev["tool"]["kind"],
                summary=str(summary)[:200],
                source=ev["source"],
                log_index=r["index"],
                untrusted_content_seen=ev["provenance"]["untrusted_content_seen"],
                latency_ms=d.get("latency_ms"),
            )
        )
        g.add(_node("Agent", agent, ev["agent_id"], agent_id=ev["agent_id"]))
        g.add(_node("Adapter", adapter, adapter_name, adapter=adapter_name))
        g.link("issues", agent, call)
        g.link("associatedWith", call, agent)
        g.link("partOf", call, run)
        g.link("governedBy", call, f"{NS}policy:{d['policy_hash']}")
        g.add(
            _node(
                "Policy",
                f"{NS}policy:{d['policy_hash']}",
                f"policy {d['policy_hash'][:12]}",
                policy_hash=d["policy_hash"],
            )
        )
        g.link("observedBy", call, adapter)
        v = d["verdict"]
        vid = f"{NS}verdict:{eid}"
        g.add(_node("Verdict", vid, f"{_verdict_attrs(v)['verdict']}", **_verdict_attrs(v)))
        g.link("produced", call, vid)
        dec = f"{NS}decider:{v.get('decided_by', 'rules')}"
        g.add(
            _node("Decider", dec, v.get("decided_by", "rules"), name=v.get("decided_by", "rules"))
        )
        g.link("decidedBy", vid, dec)
        rid = v.get("rule_id")
        if rid == "budget_exceeded":
            b = f"{NS}budget:{run_id}"
            g.add(_node("Budget", b, "budget", run_id=run_id))
            g.link("exceeded", b, vid)
        elif rid:
            short = d["policy_hash"][:16]
            rule = f"{NS}rule:{short}:{rid}"
            g.add(_node("Rule", rule, rid, rule_id=rid, origin=d.get("origin")))
            g.link("matchedRule", call, rule)
            g.link("memberOf", rule, f"{NS}policy:{d['policy_hash']}")
        if d.get("rules_verdict"):
            rv, pv = d["rules_verdict"], d.get("decider_proposed")
            rvid = f"{NS}verdict:{eid}:rules"
            g.add(
                _node(
                    "Verdict", rvid, f"rules: {_verdict_attrs(rv)['verdict']}", **_verdict_attrs(rv)
                )
            )
            rd = f"{NS}decider:{rv.get('decided_by', 'rules')}"
            g.add(
                _node(
                    "Decider", rd, rv.get("decided_by", "rules"), name=rv.get("decided_by", "rules")
                )
            )
            g.link("decidedBy", rvid, rd)
            if pv:
                pid = f"{NS}verdict:{eid}:decider"
                g.add(
                    _node(
                        "Verdict",
                        pid,
                        f"decider: {_verdict_attrs(pv)['verdict']}",
                        **_verdict_attrs(pv),
                    )
                )
                pd = f"{NS}decider:{pv.get('decided_by', 'decider')}"
                g.add(
                    _node(
                        "Decider",
                        pd,
                        pv.get("decided_by", "decider"),
                        name=pv.get("decided_by", "decider"),
                    )
                )
                g.link("decidedBy", pid, pd)
                g.link("priorVerdict", pid, rvid)
        ap = approvals.get(eid)
        if ap:
            aid = f"{NS}approval:{eid}"
            person = f"{NS}person:{ap['channel']}"
            g.add(
                _node(
                    "HumanApproval",
                    aid,
                    f"approval: {ap['outcome']}",
                    outcome=ap["outcome"],
                    channel=ap["channel"],
                )
            )
            g.add(_node("Person", person, f"human via {ap['channel']}", channel=ap["channel"]))
            g.link("approvedBy", call, aid)
            g.link("associatedWith", aid, person)
    return g


def graph_from_log(path: Path) -> Graph:
    """Verify then build. Raises SheepdogError when the log chain is broken."""
    r = verify_log(path)
    if not r.ok:
        raise SheepdogError(f"log failed verification at record {r.broken_at}: {r.reason}")
    records = [json.loads(line) for line in path.read_text().splitlines()]
    return build_graph(records)


def check_invariants(g: Graph) -> list[str]:
    """Structural invariants every run graph must satisfy; returns violations."""
    bad: list[str] = []
    for n in g.sorted_nodes():
        if n.kind == "ToolCall":
            vs = g.out(n.id, "produced")
            if len(vs) != 1:
                bad.append(f"{n.id}: {len(vs)} verdicts (exactly 1 required)")
                continue
            if g.nodes[vs[0]].a("verdict") == "ask":
                aps = g.out(n.id, "approvedBy")
                if len(aps) != 1 or g.nodes[aps[0]].a("outcome") not in OUTCOMES_OK:
                    bad.append(f"{n.id}: ask without a recorded approval or timeout deny")
            if len(g.out(n.id, "governedBy")) != 1:
                bad.append(f"{n.id}: not governed by exactly one policy")
        if n.kind == "Verdict":
            prior = g.out(n.id, "priorVerdict")
            for p in prior:
                if n.a("strictness") < g.nodes[p].a("strictness"):
                    bad.append(f"{n.id}: decider verdict looser than the rules verdict")
    return bad
