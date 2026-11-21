"""Mermaid flowchart export for READMEs and GitHub. Shows the decision structure.

LogRecord, Adapter and Person nodes are omitted to stay readable; the chain is in JSON/JSON-LD.
"""

from __future__ import annotations

import re

from sheepdogai.graph.builder import Graph

SKIP = {"LogRecord", "Adapter", "Person"}
SHAPES = {
    "Run": ("([", "])"),
    "Agent": ("[/", "/]"),
    "ToolCall": ("[", "]"),
    "Policy": ("{{", "}}"),
    "Rule": (">", "]"),
    "Verdict": ("(", ")"),
    "Decider": ("[[", "]]"),
    "Budget": ("[(", ")]"),
    "HumanApproval": ("((", "))"),
}


def _esc(s: str) -> str:
    return re.sub(r'["\[\]{}()<>|`]', " ", s).strip()[:60] or "-"


def export_mermaid(g: Graph) -> str:
    """Render the graph as a Mermaid ``flowchart LR`` (deterministic)."""
    ids: dict[str, str] = {}
    lines = ["flowchart LR"]
    for n in g.sorted_nodes():
        if n.kind in SKIP:
            continue
        ids[n.id] = f"n{len(ids)}"
        o, c = SHAPES.get(n.kind, ("[", "]"))
        label = _esc(n.label)
        if n.kind == "ToolCall":
            label += "<br/>" + _esc(str(n.a("summary", "")))
        lines.append(f'  {ids[n.id]}{o}"{label}"{c}')
    for e in g.sorted_edges():
        if e.src in ids and e.dst in ids and e.kind not in {"partOf", "associatedWith"}:
            lines.append(f"  {ids[e.src]} -->|{e.kind}| {ids[e.dst]}")
    lines.append("  classDef deny fill:#fdd,stroke:#c00;")
    lines.append("  classDef ask fill:#ffd,stroke:#a80;")
    lines.append("  classDef allow fill:#dfd,stroke:#080;")
    for n in g.sorted_nodes():
        if n.kind == "Verdict" and n.id in ids:
            lines.append(f"  class {ids[n.id]} {n.a('verdict')};")
    return "\n".join(lines) + "\n"
