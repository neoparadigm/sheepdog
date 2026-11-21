"""OpenTelemetry mapping. Optional (``pip install sheepdogai[otel]``) and OFF by default.

``spans_from_records`` is a pure function (no OTel import, no network). ``emit`` is the only code
that touches OpenTelemetry and it never runs unless the caller invokes it explicitly; the core
never calls it. Attribute names follow semantic-conventions v1.37.0 (Development stability);
everything Sheepdog-specific is under ``sheepdogai.*`` (see ontology/mapping.md).
"""

from __future__ import annotations

from typing import Any

from sheepdogai.constants import OTEL_GENAI_SEMCONV_VERSION, PACKAGE_NAME


def spans_from_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One span description per decision record."""
    run_id = records[0]["data"]["run_id"]
    phash = records[0]["data"]["policy_hash"]
    spans: list[dict[str, Any]] = []
    for r in records:
        if r["kind"] != "decision":
            continue
        d = r["data"]
        ev, v = d["event"], d["verdict"]
        attrs: dict[str, Any] = {
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": ev["tool"]["name"],
            "gen_ai.tool.call.id": ev["event_id"],
            "gen_ai.agent.id": ev["agent_id"],
            "sheepdogai.verdict": v["action"],
            "sheepdogai.verdict.reason": v.get("reason", ""),
            "sheepdogai.rule.id": v.get("rule_id") or "",
            "sheepdogai.decider": v.get("decided_by", "rules"),
            "sheepdogai.policy.hash": phash,
            "sheepdogai.adapter": d.get("adapter", ev["source"]),
            "sheepdogai.run.id": run_id,
        }
        b = d.get("budget") or {}
        if b:
            attrs["sheepdogai.budget.steps"] = b.get("steps", 0)
            attrs["sheepdogai.budget.cost_usd"] = b.get("cost_usd", 0.0)
        spans.append(
            {
                "name": f"execute_tool {ev['tool']['name']}",
                "start_time": ev["ts"],
                "attributes": attrs,
                "semconv_version": OTEL_GENAI_SEMCONV_VERSION,
            }
        )
    return spans


def emit(records: list[dict[str, Any]]) -> int:
    """Send spans through the globally configured OpenTelemetry tracer. Opt-in only."""
    try:
        from opentelemetry import trace
    except ImportError as e:
        raise ImportError("OTel export needs the extra: pip install sheepdogai[otel]") from e
    tracer = trace.get_tracer(PACKAGE_NAME)
    n = 0
    for s in spans_from_records(records):
        with tracer.start_as_current_span(s["name"], attributes=s["attributes"]):
            n += 1
    return n
