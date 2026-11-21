"""Static, self-contained HTML replay report: ``sheepdogai replay <run> --html FILE``.

One file; inline CSS only; no scripts, no external resources, no network; a strict Content-Security-
Policy forbids anything else. All text is redacted again and HTML-escaped. The same log always gives
the same bytes (no generation time is embedded: times come from the log).
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from sheepdogai.graph.builder import build_graph
from sheepdogai.graph.export_mermaid import export_mermaid
from sheepdogai.redact.secrets import redact_text

COLORS = {"allow": "#2a9d4b", "ask": "#d9a400", "deny": "#c62828"}
CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"


def _h(s: Any, limit: int = 300) -> str:
    return html.escape(redact_text(str(s))[:limit], quote=True)


def _summary(ev: dict[str, Any]) -> str:
    a = ev.get("args", {})
    return str(a.get("command") or a.get("path") or a.get("url") or "")


def render_html(records: list[dict[str, Any]]) -> str:
    """Render the report for a verified list of log records."""
    anchor = records[0]["data"]
    decisions = [r["data"] for r in records if r["kind"] == "decision"]
    approvals = {r["data"]["event_id"]: r["data"] for r in records if r["kind"] == "approval"}
    counts = {"allow": 0, "ask": 0, "deny": 0}
    for d in decisions:
        counts[d["verdict"]["action"]] += 1
    rows: list[str] = []
    flagged: list[str] = []
    strip: list[str] = []
    for i, d in enumerate(decisions):
        ev, v = d["event"], d["verdict"]
        act = v["action"]
        ap = approvals.get(ev["event_id"])
        apt = f"{_h(ap['outcome'])} via {_h(ap['channel'])}" if ap else ""
        row = (
            f'<tr class="{act}"><td>{ev["seq"]}</td><td>{_h(ev["ts"])}</td><td>{_h(ev["tool"]["name"], 80)}</td>'
            f'<td class="cmd">{_h(_summary(ev))}</td><td><b>{act}</b></td><td>{_h(v.get("rule_id") or "")}</td>'
            f"<td>{_h(v.get('decided_by', ''), 60)}</td><td>{apt}</td></tr>"
        )
        rows.append(row)
        if act != "allow" or ap:
            flagged.append(row)
        strip.append(
            f'<rect x="{i * 14}" y="0" width="12" height="22" rx="2" fill="{COLORS[act]}">'
            f"<title>{ev['seq']}: {_h(ev['tool']['name'], 40)} {act}</title></rect>"
        )
    width = max(14 * len(decisions), 14)
    mer = export_mermaid(build_graph(records))
    head = records[-1]["hash"]
    thead = "<thead><tr><th>#</th><th>time (UTC)</th><th>tool</th><th>call</th><th>verdict</th><th>rule</th><th>decided by</th><th>human</th></tr></thead>"
    css = (
        ":root{color-scheme:light dark;--bg:#fff;--fg:#1b1b1b;--mut:#666;--line:#ddd}"
        "@media(prefers-color-scheme:dark){:root{--bg:#111;--fg:#eee;--mut:#999;--line:#333}}"
        "body{font:14px/1.45 system-ui,sans-serif;margin:0 auto;max-width:1100px;padding:16px;background:var(--bg);color:var(--fg)}"
        "h1{font-size:20px}h2{font-size:16px;margin-top:28px}table{border-collapse:collapse;width:100%}"
        "th,td{border-bottom:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}"
        "td.cmd{font-family:ui-monospace,monospace;word-break:break-all}.deny b{color:#c62828}.ask b{color:#a87900}.allow b{color:#2a9d4b}"
        "pre{overflow:auto;border:1px solid var(--line);padding:8px}.mut{color:var(--mut)}.chip{display:inline-block;margin-right:12px}"
    )
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>Replay report {_h(anchor['run_id'], 80)}</title><style>{css}</style></head><body>",
        f"<h1>Replay report: run {_h(anchor['run_id'], 80)}</h1>",
        f'<p class="mut">policy hash <code>{_h(anchor["policy_hash"], 64)}</code> · schema {_h(anchor.get("schema_version", ""))} '
        f"· log head <code>{_h(head, 64)}</code> · {len(decisions)} decisions. Verify the chain with "
        f"<code>sheepdogai verify-log</code>. Secrets are redacted.</p>",
        "<p>"
        + "".join(
            f'<span class="chip"><b style="color:{COLORS[k]}">{counts[k]}</b> {k}</span>'
            for k in COLORS
        )
        + "</p>",
        "<h2>Verdict timeline</h2>",
        f'<svg role="img" aria-label="verdict timeline" width="{width}" height="22" viewBox="0 0 {width} 22">{"".join(strip)}</svg>',
        "<h2>Denied and asked calls</h2>",
        (f"<table>{thead}<tbody>{''.join(flagged)}</tbody></table>" if flagged else "<p>none</p>"),
        "<h2>All calls</h2>",
        f"<table>{thead}<tbody>{''.join(rows)}</tbody></table>",
        "<h2>Run graph (Mermaid source)</h2>",
        '<p class="mut">Paste into any Mermaid renderer (GitHub renders it in Markdown). No script is loaded here.</p>',
        f"<pre>{_h(mer, 200000)}</pre>",
        "</body></html>",
    ]
    return "\n".join(parts) + "\n"


def write_html_report(records: list[dict[str, Any]], out: Path) -> None:
    """Write the report (UTF-8, mode 0600)."""
    import os

    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, render_html(records).encode("utf-8"))
    finally:
        os.close(fd)
