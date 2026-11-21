"""``sheepdog graph`` (implemented in the graph milestone)."""

from __future__ import annotations

from pathlib import Path


def cmd_graph(run: str, project: Path, fmt: str, only_denied: bool) -> int:
    """Export a run graph."""
    raise NotImplementedError
