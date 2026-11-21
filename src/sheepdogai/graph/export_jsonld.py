"""JSON-LD export using the packaged context (inlined: no network needed to read it)."""

from __future__ import annotations

import json
from typing import Any

from sheepdogai.core.adapter import AdapterCapabilities
from sheepdogai.graph.builder import Graph
from sheepdogai.ontology import PROV_TYPE, read_text

CAP_IRI = {
    "can_block": "sheepdog:CanBlock",
    "can_ask": "sheepdog:CanAsk",
    "sees_mcp": "sheepdog:SeesMcp",
    "sees_file_edits": "sheepdog:SeesFileEdits",
}
# graph edge kind -> (JSON-LD term, invert?)
EDGE_TERM = {
    "governedBy": ("governedBy", False),
    "matchedRule": ("matchedRule", False),
    "decidedBy": ("decidedBy", False),
    "approvedBy": ("approvedBy", False),
    "exceeded": ("exceeded", False),
    "follows": ("follows", False),
    "partOf": ("partOf", False),
    "memberOf": ("memberOf", False),
    "observedBy": ("observedBy", False),
    "priorVerdict": ("priorVerdict", False),
    "associatedWith": ("wasAssociatedWith", False),
    "produced": ("wasGeneratedBy", True),
}


def _capabilities(adapter_name: str) -> list[str]:
    from sheepdogai.adapters import get_adapter
    from sheepdogai.core.errors import SheepdogError

    aliases = {"claude_code": "claude"}
    try:
        caps: AdapterCapabilities = get_adapter(
            aliases.get(adapter_name, adapter_name), experimental=True
        ).capabilities
    except SheepdogError:
        return []
    return sorted(CAP_IRI[k] for k, v in caps.model_dump().items() if v)


def jsonld_dict(g: Graph) -> dict[str, Any]:
    """Return the graph as a JSON-LD document (``@context`` inlined, ``@graph`` sorted)."""
    ctx = json.loads(read_text("context.jsonld"))["@context"]
    docs: dict[str, dict[str, Any]] = {}
    for n in g.sorted_nodes():
        d: dict[str, Any] = {"id": n.id, "type": [n.kind, PROV_TYPE[n.kind]], "label": n.label}
        a = dict(n.attrs)
        if n.kind == "Run" or n.kind == "Policy":
            d["policyHash"] = a["policy_hash"]
        elif n.kind == "ToolCall":
            d.update(
                seq=a["seq"],
                toolName=a["tool_name"],
                toolKind=a["tool_kind"],
                summary=a.get("summary", ""),
                startedAtTime=a["ts"],
                untrustedContentSeen=bool(a.get("untrusted_content_seen")),
            )
        elif n.kind == "Verdict":
            d.update(verdictValue=a["verdict"], strictness=a["strictness"])
            if a.get("reason"):
                d["reason"] = a["reason"]
        elif n.kind == "Rule":
            d["ruleId"] = a["rule_id"]
        elif n.kind in {"Decider", "Agent"}:
            d["name"] = a.get("name") or a.get("agent_id")
        elif n.kind == "HumanApproval":
            d.update(outcome=a["outcome"], channel=a["channel"])
        elif n.kind == "LogRecord":
            d.update(index=a["index"], hash=a["hash"], prevHash=a["prev_hash"])
        elif n.kind == "Adapter":
            d["name"] = a["adapter"]
            d["hasCapability"] = [{"id": c} for c in _capabilities(a["adapter"])]
        docs[n.id] = d
    for e in g.sorted_edges():
        if e.kind == "issues":  # the inverse of prov:wasAssociatedWith, already emitted
            continue
        term, invert = EDGE_TERM[e.kind]
        src, dst = (e.dst, e.src) if invert else (e.src, e.dst)
        docs[src].setdefault(term, []).append({"id": dst})
    for d in docs.values():
        for k, v in list(d.items()):
            if isinstance(v, list) and k not in {"type", "hasCapability"} and len(v) == 1:
                d[k] = v[0]
    for n in g.sorted_nodes():  # attribute decider verdicts to their decider (PROV)
        if n.kind == "Verdict":
            for dst in g.out(n.id, "decidedBy"):
                docs[n.id]["wasAttributedTo"] = {"id": dst}
    ctx = dict(ctx)
    ctx["Person"] = "prov:Person"
    return {"@context": ctx, "@graph": [docs[k] for k in sorted(docs)]}


def export_jsonld(g: Graph) -> str:
    """Serialise deterministically (sorted keys)."""
    return json.dumps(jsonld_dict(g), sort_keys=True, indent=2, ensure_ascii=True) + "\n"
