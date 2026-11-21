from datetime import UTC, datetime

import pytest

from sheepdogai.core.canonical import canonical_json, uuid7
from sheepdogai.core.decider import apply_decider
from sheepdogai.core.events import ToolCallEvent, ToolRef
from sheepdogai.core.verdict import Action, Verdict


def make_event(**kw: object) -> ToolCallEvent:
    base: dict[str, object] = dict(
        event_id=uuid7(), run_id="r", session_id="s", seq=1, ts=datetime.now(UTC),
        source="scripted", agent_id="a", tool=ToolRef(name="Bash", kind="shell"),
        args={"command": "ls"},
    )
    base.update(kw)
    return ToolCallEvent(**base)  # type: ignore[arg-type]


def test_event_roundtrip_and_frozen() -> None:
    e = make_event()
    assert ToolCallEvent.model_validate_json(e.model_dump_json()) == e
    with pytest.raises(Exception):  # noqa: B017
        e.seq = 2  # type: ignore[misc]


def test_event_rejects_bad_schema_version() -> None:
    with pytest.raises(Exception):  # noqa: B017
        make_event(schema_version="2")


def test_uuid7_shape_and_order() -> None:
    a, b = uuid7(), uuid7()
    assert a[14] == "7" and a[19] in "89ab" and len(a) == 36
    assert a[:8] <= b[:8]


def test_canonical_json_stable() -> None:
    assert canonical_json({"b": 1, "a": [1, {"z": 1, "y": 2}]}) == '{"a":[1,{"y":2,"z":1}],"b":1}'


def test_action_order() -> None:
    assert Action.ALLOW < Action.ASK < Action.DENY
    assert Action.parse("DENY") is Action.DENY
    with pytest.raises(ValueError):
        Action.parse("maybe")


class Loose:
    def decide(self, event: ToolCallEvent, prior: Verdict) -> Verdict:
        return Verdict(action=Action.ALLOW, decided_by="loose")


class Boom:
    def decide(self, event: ToolCallEvent, prior: Verdict) -> Verdict:
        raise RuntimeError("x")


class Garbage:
    def decide(self, event: ToolCallEvent, prior: Verdict) -> Verdict:
        return "allow"  # type: ignore[return-value]


def test_decider_clamp_logs_violation() -> None:
    prior = Verdict(action=Action.DENY, rule_id="r1", reason="no")
    v, note = apply_decider(Loose(), make_event(), prior)
    assert v == prior and note and note.startswith("decider_violation")


def test_decider_crash_fails_closed() -> None:
    prior = Verdict(action=Action.ALLOW)
    for d in (Boom(), Garbage()):
        v, note = apply_decider(d, make_event(), prior)  # type: ignore[arg-type]
        assert v.action is Action.DENY and note and note.startswith("decider_error")


def test_decider_may_tighten() -> None:
    class Tight:
        def decide(self, event: ToolCallEvent, prior: Verdict) -> Verdict:
            return Verdict(action=Action.ASK, decided_by="tight")

    v, note = apply_decider(Tight(), make_event(), Verdict(action=Action.ALLOW))
    assert v.action is Action.ASK and note is None
