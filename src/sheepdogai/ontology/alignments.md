# Aligning with other agent ontologies

Status: **no alignment is implemented or tested.** This file only explains how one could be done
without claiming it. Do not cite an alignment from this project until a test exists.

Candidate approach for an ontology such as AgentO (or any agent-oriented vocabulary):

1. Keep PROV-O as the shared layer: `sheepdog:Agent` is a `prov:SoftwareAgent`, `sheepdog:ToolCall`
   a `prov:Activity`. Another ontology that also builds on PROV-O is then already compatible at
   that level.
2. Add a separate alignment file (for example `alignments.ttl`) with `rdfs:subClassOf` /
   `owl:equivalentClass` / `rdfs:subPropertyOf` axioms **in one direction** (Sheepdog term to the
   other ontology's term), never edits to `sheepdog.ttl`.
3. Add a test that loads both graphs, runs the axioms and checks one real exported run for the
   expected inferred types. Only then list the alignment in the README.
4. Do not align `sheepdog:Verdict`/`sheepdog:strictness`: they have no counterpart in general agent
   ontologies and their strictness ordering is enforced by SHACL, not by OWL inference.
