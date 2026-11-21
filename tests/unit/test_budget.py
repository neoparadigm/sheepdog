from pathlib import Path

from tests.helpers import event, make_engine

from sheepdogai.budget.guard import BudgetGuard
from sheepdogai.core.verdict import Action, BudgetState


def test_201st_step_denied(tmp_path: Path) -> None:
    eng = make_engine(
        tmp_path, mode="relaxed", packs=[], budget={"max_steps": 200, "max_repeats": 999}
    )
    st = BudgetState()
    for i in range(200):
        d = eng.decide(event(f"echo {i}", cwd=str(tmp_path), seq=i), st)
        assert d.verdict.action is Action.ALLOW, i
        st = d.budget
    d = eng.decide(event("echo extra", cwd=str(tmp_path), seq=201), st)
    assert d.verdict.action is Action.DENY and d.verdict.rule_id == "budget_exceeded"
    assert "budget_exceeded" in d.verdict.reason and d.budget.exceeded


def test_three_identical_failing_calls_trigger_repeat_limit(tmp_path: Path) -> None:
    eng = make_engine(tmp_path, mode="relaxed", packs=[], budget={"max_repeats": 3})
    st = BudgetState()
    for i in range(3):
        d = eng.decide(event("make test", cwd=str(tmp_path), seq=i), st)
        assert d.verdict.action is Action.ALLOW
        st = BudgetGuard.record_outcome(d.budget, failed=True)
    d = eng.decide(event("make test", cwd=str(tmp_path), seq=4), st)
    assert d.verdict.action is Action.DENY and "repeated" in d.verdict.reason


def test_success_resets_repeats(tmp_path: Path) -> None:
    eng = make_engine(tmp_path, mode="relaxed", packs=[], budget={"max_repeats": 2})
    st = BudgetState()
    for i in range(6):
        d = eng.decide(event("make test", cwd=str(tmp_path), seq=i), st)
        assert d.verdict.action is Action.ALLOW, i
        st = BudgetGuard.record_outcome(d.budget, failed=False)


def test_different_call_resets(tmp_path: Path) -> None:
    eng = make_engine(tmp_path, mode="relaxed", packs=[], budget={"max_repeats": 1})
    st = BudgetState()
    for i, c in enumerate(["a", "b", "a", "b"]):
        d = eng.decide(event(c, cwd=str(tmp_path), seq=i), st)
        assert d.verdict.action is Action.ALLOW
        st = d.budget


def test_cost_unknown_is_stated_and_cost_known_enforced(tmp_path: Path) -> None:
    eng = make_engine(tmp_path, mode="relaxed", packs=[], budget={"max_cost_usd": 1})
    d = eng.decide(event("x", cwd=str(tmp_path)))
    assert any("steps only" in n for n in d.notes)
    st = BudgetGuard.record_usage(d.budget, 2.0)
    d2 = eng.decide(event("y", cwd=str(tmp_path)), st)
    assert d2.verdict.action is Action.DENY and any("steps+cost" in n for n in d2.notes)


def test_budget_beats_allow_rule_but_not_self_protect_reason(tmp_path: Path) -> None:
    eng = make_engine(
        tmp_path,
        mode="relaxed",
        packs=[],
        budget={"max_steps": 1},
        rules=[{"id": "all", "match": {"tool": "Bash"}, "action": "allow"}],
    )
    st = eng.decide(event("a", cwd=str(tmp_path))).budget
    d = eng.decide(event("b", cwd=str(tmp_path)), st)
    assert d.verdict.rule_id == "budget_exceeded"
    d = eng.decide(
        event(kind="file_write", name="Write", file_path="sheepdog.yaml", cwd=str(tmp_path)), st
    )
    assert (
        d.origin == "self_protect"
        and d.verdict.action is Action.ASK
        or d.verdict.action is Action.DENY
    )
