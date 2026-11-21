"""Render the benchmark results as Markdown. Never writes the word 'secure'."""

from __future__ import annotations

from typing import Any


def _ci(ci: tuple[float, float], pct: bool = True) -> str:
    return f"{ci[0] * 100:.1f}-{ci[1] * 100:.1f}%" if pct else f"{ci[0]:.2f}-{ci[1]:.2f}"


def render(res: dict[str, Any]) -> str:
    """Markdown report: header (reproducibility), table, and every attack that got through."""
    v = res["corpus_version"]
    L: list[str] = [f"# Injection gauntlet report (corpus {v})", ""]
    L += [
        "| | |",
        "|---|---|",
        f"| corpus version | `{v}` |",
        f"| corpus sha256 | `{res['corpus_sha256']}` |",
        f"| policy hash | `{res['policy_hash']}` |",
        f"| mode | `{res['mode']}` |",
        f"| scenarios / instances | {res['scenarios']} / {res['instances']} (instances include obfuscated variants) |",
        f"| sheepdogai | {res['sheepdogai_version']} |",
        f"| machine | {res['platform']} {res['machine']}, Python {res['python']} |",
        "",
        "Reproduce: `make bench` (no network, no model calls). Intervals are 95% (Wilson for rates, "
        "bootstrap with a fixed seed for latency/CPU).",
        "",
    ]
    L += [
        "## Results",
        "",
        "| adapter | blocked (deny or ask) | block rate | of which hard-denied | false positives (benign hard-denied) | benign friction (ask) | p50 ms | p95 ms | CPU ms / 1,000 decisions |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for a, d in res["adapters"].items():
        s = d["summary"]
        exp = " (experimental)" if a == "codex" else ""
        L.append(
            f"| {a}{exp} | blocked {s['blocked']} of {s['attacks']} scenarios in corpus {v} "
            f"| {s['block_rate'] * 100:.1f}% [{_ci(s['block_ci'])}] "
            f"| {s['hard_denied']} of {s['attacks']} [{_ci(s['hard_ci'])}] "
            f"| {s['false_positives']} of {s['benign']} = {s['fp_rate'] * 100:.1f}% [{_ci(s['fp_ci'])}] "
            f"| {s['friction']} of {s['benign']} = {s['friction_rate'] * 100:.1f}% [{_ci(s['friction_ci'])}] "
            f"| {s['p50_ms']:.2f} [{_ci(s['p50_ci'], False)}] | {s['p95_ms']:.2f} [{_ci(s['p95_ci'], False)}] "
            f"| {s['cpu_ms_per_1000']:.0f} [{_ci(s['cpu_ci_per_1000'], False)}] |"
        )
    L += [
        "",
        "Notes",
        "",
        "* *Blocked* means the harmful step was denied, or turned into a question for a human. "
        "Gemini CLI and Codex cannot ask, so for them every ask becomes a deny.",
        "* *False positive* counts only hard denies of benign look-alikes; *friction* counts asks "
        "(and, for CLIs that cannot ask, asks downgraded to deny).",
        "* Latency is the in-process gateway (parse, decide, fsynced log write); it excludes "
        "interpreter start-up of the hook process. Cost: no model or API calls are made, so "
        "model cost is $0.00; the CPU figure is the measured process CPU time.",
        "* The corpus was written by the same people who wrote the rules. It measures regressions "
        "and known gaps; it is **not** an independent adversarial evaluation.",
        "",
    ]
    for a, d in res["adapters"].items():
        s = d["summary"]
        L += [f"## Attacks that got through: {a}", ""]
        if not s["got_through"]:
            L += ["none", ""]
            continue
        L += ["| scenario | category | expected gap | command / target |", "|---|---|---|---|"]
        for g in s["got_through"]:
            c = g["command"].replace("|", "\\|").replace("\n", " ")
            L.append(
                f"| {g['id']} | {g['category']} | {'yes' if g['known_gap'] else '**NO (regression)**'} | `{c}` |"
            )
        L.append("")
        if s["false_positive_list"]:
            L += [f"## Benign scenarios hard-denied: {a}", ""]
            L += [
                f"* {x['id']} (rule `{x['rule']}`): `{x['command']}`"
                for x in s["false_positive_list"]
            ] + [""]
    return "\n".join(L) + "\n"
