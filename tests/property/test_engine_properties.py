from __future__ import annotations

from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from tests.helpers import event, event_raw, make_engine

from sheepdogai.core.canonical import canonical_json
from sheepdogai.core.decider import apply_decider
from sheepdogai.core.events import ToolCallEvent
from sheepdogai.core.verdict import Action, Verdict
from sheepdogai.policy.engine import PolicyEngine

PROJ = Path("/nonexistent/proj")
ENG = make_engine(PROJ, mode="strict")
SETTINGS = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])

cmds = st.text(max_size=300)
kinds = st.sampled_from(["shell", "file_read", "file_write", "network", "mcp", "other"])
json_leaf = st.none() | st.booleans() | st.integers() | st.text(max_size=50)
args = st.dictionaries(
    st.text(max_size=10), json_leaf | st.lists(json_leaf, max_size=3), max_size=5
)


@SETTINGS
@given(cmd=cmds)
def test_engine_total_on_arbitrary_commands(cmd: str) -> None:
    d = ENG.decide(event(cmd, cwd=str(PROJ)))
    assert isinstance(d.verdict.action, Action)


@SETTINGS
@given(kind=kinds, a=args, cwd=st.none() | st.text(max_size=30))
def test_engine_total_on_arbitrary_events(kind: str, a: dict[str, object], cwd: str | None) -> None:
    e = event_raw(kind, a, cwd)  # type: ignore[arg-type]
    d = ENG.decide(e)
    assert d.verdict.action in (Action.ALLOW, Action.ASK, Action.DENY)


@SETTINGS
@given(prior=st.sampled_from(list(Action)), out=st.sampled_from(list(Action)))
def test_decider_can_never_loosen(prior: Action, out: Action) -> None:
    class D:
        def decide(self, event: ToolCallEvent, prior: Verdict) -> Verdict:
            return Verdict(action=out, decided_by="d")

    v, _ = apply_decider(D(), event("x"), Verdict(action=prior, rule_id="r"))
    assert v.action >= prior


@SETTINGS
@given(cmd=cmds, out=st.sampled_from(list(Action)))
def test_engine_with_decider_never_loosens_rules_verdict(cmd: str, out: Action) -> None:
    class D:
        def decide(self, event: ToolCallEvent, prior: Verdict) -> Verdict:
            return Verdict(action=out, decided_by="d")

    base = ENG.decide(event(cmd, cwd=str(PROJ)))
    wrapped = PolicyEngine(ENG.policy, decider=D()).decide(event(cmd, cwd=str(PROJ)))
    assert wrapped.verdict.action >= base.verdict.action


@SETTINGS
@given(
    actions=st.lists(
        st.sampled_from(["allow", "ask", "deny"]), min_size=1, max_size=6, unique=False
    )
)
def test_rule_order_first_match_wins(actions: list[str]) -> None:
    rules = [
        {"id": f"r{i}", "match": {"command": f"echo {i}*" if i else "echo*"}, "action": a}
        for i, a in enumerate(actions)
    ]
    # rule 0 matches everything the others could, so only r0 is reachable; loader would reject
    # the shadowed ones, so build distinct disjoint matchers instead:
    rules = [
        {"id": f"r{i}", "match": {"command": f"echo {i}"}, "action": a}
        for i, a in enumerate(actions)
    ] + [{"id": "tail", "match": {"tool": "Bash"}, "action": "deny"}]
    eng = make_engine(
        PROJ, packs=[], rules=rules, mode="relaxed", budget={"max_steps": 1000, "max_repeats": 1000}
    )
    for i, a in enumerate(actions):
        d = eng.decide(event(f"echo {i}", cwd=str(PROJ)))
        assert d.verdict.rule_id == f"r{i}" and d.verdict.action.label == a


@SETTINGS
@given(
    obj=st.recursive(
        json_leaf,
        lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=5), c, max_size=4),
        max_leaves=20,
    )
)
def test_canonical_json_stable(obj: object) -> None:
    import json

    a = canonical_json(obj)
    assert canonical_json(json.loads(a)) == a
    if isinstance(obj, dict):
        assert canonical_json(dict(reversed(list(obj.items())))) == a
