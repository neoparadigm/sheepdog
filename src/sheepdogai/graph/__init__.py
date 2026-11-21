"""Run graph: built from the log, exported as Mermaid, JSON and JSON-LD."""

from __future__ import annotations

from sheepdogai.graph.builder import Graph


def only_denied(g: Graph) -> Graph:
    """Keep only denied tool calls with their neighbourhood (verdict, rule, decider, agent...)."""
    keep: set[str] = set()
    for n in g.sorted_nodes():
        if n.kind == "ToolCall":
            vs = g.out(n.id, "produced")
            if vs and g.nodes[vs[0]].a("verdict") == "deny":
                keep.add(n.id)
                keep.update(vs)
                for k in ("matchedRule", "governedBy", "observedBy"):
                    keep.update(g.out(n.id, k))
                keep.update(e.src for e in g.edges if e.kind == "issues" and e.dst == n.id)
                for v in vs:
                    keep.update(g.out(v, "decidedBy"))
                keep.update(e.src for e in g.edges if e.kind == "exceeded" and e.dst in vs)
    out = Graph()
    for k in keep:
        out.add(g.nodes[k])
    out.edges = {e for e in g.edges if e.src in keep and e.dst in keep}
    return out
