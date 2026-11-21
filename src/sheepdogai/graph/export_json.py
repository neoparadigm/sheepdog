"""Deterministic JSON export (stable key order, same log -> same bytes)."""

from __future__ import annotations

import json
from typing import Any

from sheepdogai.graph.builder import Graph


def graph_dict(g: Graph) -> dict[str, Any]:
    """Plain-dict form of the graph, sorted."""
    return {
        "nodes": [
            {"id": n.id, "kind": n.kind, "label": n.label, "attrs": dict(n.attrs)}
            for n in g.sorted_nodes()
        ],
        "edges": [{"kind": e.kind, "src": e.src, "dst": e.dst} for e in g.sorted_edges()],
    }


def export_json(g: Graph) -> str:
    """Serialise with sorted keys and a trailing newline."""
    return json.dumps(graph_dict(g), sort_keys=True, indent=2, ensure_ascii=True) + "\n"
