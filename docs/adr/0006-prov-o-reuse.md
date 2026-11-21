# 0006. Reuse W3C PROV-O; add a small sheepdogai: vocabulary

Status: accepted

## Decision
Runs, tool calls, agents, plans and entities map to PROV-O classes. Only what PROV-O and OTel lack
(verdicts, approvals, budgets, adapter capabilities, strictness ordering) is defined under
`sheepdogai:`. Event IRIs are `urn:sheepdogai:event:<uuid7>` so graphs merge. OTel `gen_ai.*` names are
mapped only after checking them against semantic-conventions v1.37.0 (Development stability) and the
version is pinned in `constants.py`. The namespace `https://example.org/sheepdogai#` is a placeholder.
SHACL shapes are part of the contract, not a nice-to-have.

## Consequences
Exports are readable by generic RDF tooling. We make no claim of alignment with other agent
ontologies (see `ontology/alignments.md`).
