"""Validate a run's JSON-LD export against shapes.ttl. Needs the optional ``rdf`` extra."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sheepdogai.ontology import read_text


@dataclass(frozen=True)
class ValidationReport:
    """Result of SHACL validation."""

    conforms: bool
    text: str


def load_data_graph(doc: dict[str, Any] | str) -> Any:
    """Parse a JSON-LD document (already containing its inline context) into an rdflib Graph."""
    from rdflib import Graph

    data = doc if isinstance(doc, str) else json.dumps(doc)
    g = Graph()
    g.parse(data=data, format="json-ld")
    return g


def validate_export(doc: dict[str, Any] | str) -> ValidationReport:
    """Validate against the packaged shapes. Raises ImportError if rdflib/pyshacl are missing."""
    try:
        from pyshacl import validate
        from rdflib import Graph
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "ontology validation needs the 'rdf' extra: pip install sheepdogai[rdf]"
        ) from e
    data = load_data_graph(doc)
    shapes = Graph()
    shapes.parse(data=read_text("shapes.ttl"), format="turtle")
    ont = Graph()
    ont.parse(data=read_text("sheepdog.ttl"), format="turtle")
    conforms, _g, text = validate(
        data,
        shacl_graph=shapes,
        ont_graph=ont,
        inference="none",
        advanced=True,
        allow_warnings=False,
    )
    return ValidationReport(bool(conforms), str(text))
