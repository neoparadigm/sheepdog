from __future__ import annotations

from pathlib import Path

from sheepdogai.cli.replay import read_records, replay_records
from sheepdogai.policy.loader import load_policy

GOLD = Path(__file__).resolve().parent / "golden"


def test_golden_run_replays_to_identical_verdicts() -> None:
    pol = load_policy(GOLD / "sheepdogai.yaml", project_root=Path("/work/proj"))
    recs = read_records(GOLD / "run.jsonl")
    assert recs[0]["data"]["policy_hash"] == pol.policy_hash
    diffs, n = replay_records(recs, pol)
    assert n == 10 and diffs == []


def test_rule_change_shows_exactly_the_diff() -> None:
    text = (GOLD / "sheepdogai.yaml").read_text().replace("action: allow", "action: deny")
    alt = GOLD.parent / "_alt.yaml"
    alt.write_text(text)
    try:
        pol = load_policy(alt, project_root=Path("/work/proj"))
        diffs, _ = replay_records(read_records(GOLD / "run.jsonl"), pol)
    finally:
        alt.unlink()
    assert [(d.seq, d.recorded, d.now, d.now_rule) for d in diffs] == [
        (1, "allow", "deny", "allow-echo")
    ]
