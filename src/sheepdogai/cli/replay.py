"""``sheepdog replay <run>``: re-feed recorded events through the current policy.

Deterministic: no clock, no randomness, no model calls. If the run was recorded with a
non-rules Decider, the *recorded* answers are replayed through the engine's clamp. Path
resolution reads the filesystem (realpath), so symlink changes since recording can change
results; events are replayed in their logged (redacted, length-compacted) form.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sheepdogai.cli.verify_log import resolve_run
from sheepdogai.constants import CONFIG_FILE
from sheepdogai.core.errors import SheepdogError
from sheepdogai.core.events import ToolCallEvent
from sheepdogai.core.verdict import Action, BudgetState, Verdict
from sheepdogai.log.verify import verify_log
from sheepdogai.policy.engine import PolicyEngine
from sheepdogai.policy.loader import Policy, load_policy

RULES_DECIDERS = {"rules", "engine", "budget"}


@dataclass(frozen=True)
class Diff:
    """One verdict that differs between the recording and the current policy."""

    seq: int
    tool: str
    recorded: str
    recorded_rule: str | None
    now: str
    now_rule: str | None
    inexact: bool = False


class RecordedDecider:
    """Replays recorded non-rules Decider answers; never calls a model."""

    def __init__(self, recorded: dict[str, Verdict]) -> None:
        self.recorded = recorded

    def decide(self, event: ToolCallEvent, prior: Verdict) -> Verdict:
        """Return the recorded answer for this event, or the prior if none was recorded."""
        return self.recorded.get(event.event_id, prior)


def read_records(path: Path) -> list[dict[str, Any]]:
    """Read and verify a run log; raises SheepdogError when the chain is broken."""
    r = verify_log(path)
    if not r.ok:
        raise SheepdogError(f"log failed verification at record {r.broken_at}: {r.reason}")
    return [json.loads(line) for line in path.read_text().splitlines()]


def replay_records(records: list[dict[str, Any]], policy: Policy) -> tuple[list[Diff], int]:
    """Replay decision records through ``policy``. Returns (diffs, decisions replayed)."""
    from sheepdogai.adapters import get_adapter

    decisions = [r["data"] for r in records if r["kind"] == "decision"]
    recorded: dict[str, Verdict] = {}
    for d in decisions:
        v = d["verdict"]
        if v.get("decided_by") not in RULES_DECIDERS:
            recorded[d["event"]["event_id"]] = Verdict.model_validate(v)
    eng = PolicyEngine(policy, decider=RecordedDecider(recorded) if recorded else None)
    state = BudgetState()
    diffs: list[Diff] = []
    for d in decisions:
        ev = ToolCallEvent.model_validate(d["event"])
        try:
            caps = get_adapter(d.get("adapter", "claude"), experimental=True).capabilities
        except SheepdogError:
            caps = None
        out = eng.decide(ev, state, caps)
        state = out.budget
        old = d["verdict"]
        old_action = Action.parse(
            old["action"] if isinstance(old["action"], str) else Action(old["action"]).name
        )
        if out.verdict.action != old_action or out.verdict.rule_id != old.get("rule_id"):
            diffs.append(
                Diff(
                    ev.seq,
                    ev.tool.name,
                    old_action.label,
                    old.get("rule_id"),
                    out.verdict.action.label,
                    out.verdict.rule_id,
                    inexact=any("cut;" in json.dumps(ev.args) for _ in (0,)),
                )
            )
    return diffs, len(decisions)


def cmd_replay(run: str, project: Path, html: str | None = None) -> int:
    """Replay a run; exit 0 when nothing differs, 1 otherwise."""
    path = resolve_run(run, project)
    records = read_records(path)
    rules = project / CONFIG_FILE
    policy = load_policy(rules if rules.exists() else None, project_root=project)
    diffs, n = replay_records(records, policy)
    anchor = records[0]["data"].get("policy_hash", "")
    print(
        f"replayed {n} decisions; recorded policy {anchor[:12]}, current policy {policy.policy_hash[:12]}"
    )
    for d in diffs:
        note = " (args were length-compacted in the log; may be inexact)" if d.inexact else ""
        print(
            f"  seq {d.seq} {d.tool}: {d.recorded}[{d.recorded_rule}] -> {d.now}[{d.now_rule}]{note}"
        )
    print(f"{len(diffs)} verdict(s) differ")
    if html:
        from sheepdogai.cli.report import write_html_report

        write_html_report(records, Path(html))
        print(f"wrote {html}")
    return 1 if diffs else 0
