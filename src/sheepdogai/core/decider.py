"""Decider protocol and the clamp that enforces invariant 2 (stricter only)."""

from __future__ import annotations

from typing import Protocol

from sheepdogai.core.events import ToolCallEvent
from sheepdogai.core.verdict import Action, Verdict


class Decider(Protocol):
    """Optional second opinion. Result must be >= prior in strictness."""

    def decide(self, event: ToolCallEvent, prior: Verdict) -> Verdict:
        """Return a verdict at least as strict as ``prior``."""
        ...


def apply_decider(
    decider: Decider, event: ToolCallEvent, prior: Verdict
) -> tuple[Verdict, str | None]:
    """Run ``decider`` and clamp the result; see :func:`apply_decider_ex`."""
    v, note, _ = apply_decider_ex(decider, event, prior)
    return v, note


def apply_decider_ex(
    decider: Decider, event: ToolCallEvent, prior: Verdict
) -> tuple[Verdict, str | None, Verdict | None]:
    """Run ``decider`` and clamp the result.

    The third element is the decider's raw proposal (None if it crashed), kept so the run graph
    can show a violation.

    Returns ``(verdict, note, proposed)``. ``note`` is ``decider_violation: ...`` when the decider
    tried to loosen the verdict (the prior is returned) or ``decider_error: ...`` when it
    raised or returned garbage (fail closed: deny).
    """
    try:
        out = decider.decide(event, prior)
        if not isinstance(out, Verdict):
            raise TypeError("decider returned a non-Verdict")
    except Exception as e:
        return (
            Verdict(
                action=Action.DENY,
                rule_id=prior.rule_id,
                reason=f"decider failed ({type(e).__name__}); failing closed",
                decided_by="engine",
            ),
            f"decider_error: {type(e).__name__}",
            None,
        )
    if out.action < prior.action:
        return (
            prior,
            f"decider_violation: {out.decided_by} returned {out.action.label} "
            f"for prior {prior.action.label}; clamped",
            out,
        )
    return out, None, out
