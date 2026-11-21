# Sheepdog ontology

A small vocabulary (`sheepdog.ttl`) for what PROV-O and OpenTelemetry do not cover: policy
verdicts, approvals, budgets and adapter capabilities. Everything else reuses W3C PROV-O.

| File | Purpose |
|---|---|
| `sheepdog.ttl` | OWL vocabulary. Namespace `https://example.org/sheepdog#` is a **placeholder** (`constants.ONTOLOGY_NS`). |
| `context.jsonld` | JSON-LD context: any exported event or decision reads as RDF. |
| `shapes.ttl` | SHACL shapes every exported graph must satisfy (incl. "a Decider may only tighten"). |
| `mapping.md` | Sheepdog / PROV-O / OTel table, checked by a test. |
| `validate.py` | `validate_export(doc)`; needs `pip install sheepdogai[rdf]`. |
| `alignments.md` | How to align with other agent ontologies. Nothing is claimed that is not tested. |

## Worked example: one denied tool call

The agent runs `rm -rf /`. The adapter normalises it to one event:

```json
{"schema_version": "1", "event_id": "0197c8a2-6f0e-7b3a-9c1d-2d6f4a5b7c10", "run_id": "abc123",
 "seq": 1, "source": "claude_code", "agent_id": "claude_code",
 "tool": {"name": "Bash", "kind": "shell"}, "args": {"command": "rm -rf /"}}
```

`sheepdog graph abc123 --format jsonld` exports (abridged):

```json
{"@context": "…inlined from context.jsonld…",
 "@graph": [
  {"id": "urn:sheepdog:event:0197c8a2-6f0e-7b3a-9c1d-2d6f4a5b7c10", "type": ["ToolCall", "prov:Activity"],
   "toolName": "Bash", "summary": "rm -rf /", "seq": 1,
   "wasAssociatedWith": {"id": "urn:sheepdog:agent:claude_code"},
   "governedBy": {"id": "urn:sheepdog:policy:03f6…"},
   "matchedRule": {"id": "urn:sheepdog:rule:03f6…:machine-recursive-delete-outside"}},
  {"id": "urn:sheepdog:verdict:0197c8a2-…", "type": ["Verdict", "prov:Entity"],
   "verdictValue": "deny", "strictness": 2,
   "wasGeneratedBy": {"id": "urn:sheepdog:event:0197c8a2-…"},
   "decidedBy": {"id": "urn:sheepdog:decider:rules"}}]}
```

The same facts as Turtle:

```turtle
<urn:sheepdog:event:0197c8a2-…> a sheepdog:ToolCall, prov:Activity ;
    sheepdog:toolName "Bash" ;
    prov:wasAssociatedWith <urn:sheepdog:agent:claude_code> ;
    sheepdog:governedBy <urn:sheepdog:policy:03f6…> ;
    sheepdog:matchedRule <urn:sheepdog:rule:03f6…:machine-recursive-delete-outside> .
<urn:sheepdog:verdict:0197c8a2-…> a sheepdog:Verdict, prov:Entity ;
    sheepdog:verdictValue "deny" ; sheepdog:strictness 2 ;
    prov:wasGeneratedBy <urn:sheepdog:event:0197c8a2-…> ;
    sheepdog:decidedBy <urn:sheepdog:decider:rules> .
```

IRIs are stable per event (`urn:sheepdog:event:<uuid7>`), so graphs from different runs merge.
`tests/ontology/test_ontology.py` builds this exact scenario and asserts the triples.
