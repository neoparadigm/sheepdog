"""Budget guard: steps, estimated cost and consecutive repeats of the same failing call."""

from __future__ import annotations

from sheepdogai.core.canonical import canonical_json, sha256_hex
from sheepdogai.core.events import ToolCallEvent
from sheepdogai.core.verdict import Action, BudgetState, Verdict
from sheepdogai.policy.schema import BudgetConfig

BUDGET_RULE_ID = "budget_exceeded"


def fingerprint(event: ToolCallEvent) -> str:
    """Stable identity of a call (tool + args), used to detect repeats."""
    return sha256_hex(canonical_json({"t": event.tool.name, "a": event.args}))[:16]


class BudgetGuard:
    """Pure transitions over :class:`BudgetState`; the caller owns the state.

    * steps: the (max_steps + 1)-th call is denied.
    * cost: counted only when the adapter reports usage via :meth:`record_usage`; otherwise the
      log says ``steps only`` (see :meth:`basis`).
    * repeats: ``repeats`` counts earlier consecutive identical calls whose outcome was not a
      success (:meth:`record_outcome`). With max_repeats=3 the first three identical calls pass
      and the fourth is denied. Without outcome feedback (PreToolUse
      hooks cannot see results) identical consecutive calls are counted instead; that is stricter.
    """

    def __init__(self, cfg: BudgetConfig) -> None:
        self.cfg = cfg

    def check(self, event: ToolCallEvent, state: BudgetState) -> tuple[BudgetState, Verdict | None]:
        """Advance the state for ``event``; return a deny verdict when a limit is hit."""
        fp = fingerprint(event)
        same = state.last_fingerprint == fp and state.last_failed is not False
        repeats = state.repeats + 1 if same else 0
        new = state.model_copy(
            update={
                "steps": state.steps + 1,
                "repeats": repeats,
                "last_fingerprint": fp,
                "last_failed": None,
            }
        )
        reason = None
        if state.steps + 1 > self.cfg.max_steps:
            reason = f"step limit {self.cfg.max_steps} reached"
        elif state.cost_known and state.cost_usd > self.cfg.max_cost_usd:
            reason = f"cost limit ${self.cfg.max_cost_usd:g} reached"
        elif repeats >= self.cfg.max_repeats:
            reason = f"call repeated more than {self.cfg.max_repeats} times"
        if reason:
            new = new.model_copy(update={"exceeded": reason})
            return new, Verdict(
                action=Action.DENY,
                rule_id=BUDGET_RULE_ID,
                reason=f"budget_exceeded: {reason}",
                decided_by="budget",
            )
        return new, None

    @staticmethod
    def record_usage(state: BudgetState, cost_usd: float) -> BudgetState:
        """Add adapter-reported cost."""
        return state.model_copy(update={"cost_usd": state.cost_usd + cost_usd, "cost_known": True})

    @staticmethod
    def record_outcome(state: BudgetState, failed: bool) -> BudgetState:
        """Record whether the last call failed (from a PostToolUse-style signal)."""
        return state.model_copy(update={"last_failed": failed})

    @staticmethod
    def basis(state: BudgetState) -> str:
        """What the cost number is based on, for the log."""
        return "steps+cost" if state.cost_known else "steps only (no adapter-reported cost)"
