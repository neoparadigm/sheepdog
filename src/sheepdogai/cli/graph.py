"""``sheepdog graph <run> --format mermaid|json|jsonld [--only-denied]``."""

from __future__ import annotations

from pathlib import Path

from sheepdogai.cli.verify_log import resolve_run
from sheepdogai.graph import only_denied
from sheepdogai.graph.builder import graph_from_log
from sheepdogai.graph.export_json import export_json
from sheepdogai.graph.export_jsonld import export_jsonld
from sheepdogai.graph.export_mermaid import export_mermaid


def cmd_graph(run: str, project: Path, fmt: str, denied_only: bool) -> int:
    """Print the graph; deterministic output (same log, same bytes)."""
    g = graph_from_log(resolve_run(run, project))
    if denied_only:
        g = only_denied(g)
    out = {"mermaid": export_mermaid, "json": export_json, "jsonld": export_jsonld}[fmt](g)
    print(out, end="")
    return 0
