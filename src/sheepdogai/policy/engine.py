"""The policy engine: total, deterministic, first match wins, Decider can only tighten."""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field

from sheepdogai.budget.guard import BudgetGuard
from sheepdogai.core.adapter import AdapterCapabilities
from sheepdogai.core.decider import Decider, apply_decider
from sheepdogai.core.errors import RulesError
from sheepdogai.core.events import ToolCallEvent
from sheepdogai.core.verdict import Action, BudgetState, Verdict
from sheepdogai.policy.loader import Policy
from sheepdogai.policy.matchers import Facts, compute_facts

_READ_KINDS = {"file_read"}


@dataclass
class Decision:
    """Engine output for one event."""

    verdict: Verdict
    notes: list[str] = field(default_factory=list)
    budget: BudgetState = field(default_factory=BudgetState)
    origin: str = "engine"


def load_decider(spec: str) -> Decider | None:
    """Build the configured Decider. ``rules`` means none. Unknown/unimplemented types fail."""
    if spec == "rules":
        return None
    if spec.startswith("python:"):
        parts = spec.split(":")
        if len(parts) != 3 or not all(parts[1:]):
            raise RulesError(f"decider {spec!r}: expected python:<module>:<class>")
        try:
            cls = getattr(importlib.import_module(parts[1]), parts[2])
            inst: Decider = cls()
        except Exception as e:
            raise RulesError(f"decider {spec!r} could not be loaded: {e}") from e
        return inst
    raise RulesError(f"decider type {spec!r} is not implemented in this version")


class PolicyEngine:
    """Evaluate events against a :class:`Policy`."""

    def __init__(self, policy: Policy, decider: Decider | None = None) -> None:
        self.policy = policy
        self.decider = decider if decider is not None else load_decider(policy.config.decider.type)
        self.guard = BudgetGuard(policy.budget)

    def decide(
        self,
        event: ToolCallEvent,
        state: BudgetState | None = None,
        caps: AdapterCapabilities | None = None,
        facts: Facts | None = None,
    ) -> Decision:
        """Always returns a Decision. Any internal error yields deny."""
        state = state or BudgetState()
        try:
            return self._decide(event, state, caps, facts)
        except Exception as e:
            return Decision(
                Verdict(
                    action=Action.DENY,
                    rule_id="engine_error",
                    reason=f"internal error ({type(e).__name__}); failing closed",
                    decided_by="engine",
                ),
                [f"engine_error: {type(e).__name__}"],
                state,
                "engine",
            )

    def _default(self, f: Facts) -> Verdict:
        mode = self.policy.config.mode
        if mode == "relaxed":
            return Verdict(
                action=Action.ALLOW, rule_id="default.relaxed", reason="no rule matched (relaxed)"
            )
        if mode == "balanced" and self._read_only(f):
            return Verdict(
                action=Action.ALLOW,
                rule_id="default.balanced",
                reason="no rule matched; read-only call (balanced)",
            )
        return Verdict(
            action=Action.ASK,
            rule_id=f"default.{mode}",
            reason=f"no rule matched ({mode} mode asks)",
        )

    @staticmethod
    def _read_only(f: Facts) -> bool:
        if f.event.tool.kind in _READ_KINDS:
            return not f.mutates
        if f.event.tool.kind == "shell" and f.parsed is not None:
            return (
                not f.mutates
                and not f.network_use
                and not f.parsed.opaque
                and not f.parsed.pipe_to_shell
                and bool(f.parsed.segments)
            )
        return False

    def _decide(
        self,
        event: ToolCallEvent,
        state: BudgetState,
        caps: AdapterCapabilities | None,
        facts: Facts | None,
    ) -> Decision:
        notes: list[str] = []
        f = facts or compute_facts(
            event,
            self.policy.project_root,
            self.policy.home,
            tuple(self.policy.config.settings.scratch_paths),
        )
        if f.parsed and f.parsed.notes:
            notes.extend(f"normaliser:{n}" for n in f.parsed.notes)
        if f.extra.get("facts_error"):
            notes.append(f"facts_error:{f.extra['facts_error']}")
        new_state, budget_verdict = self.guard.check(event, state)
        notes.append(f"budget_basis: {self.guard.basis(new_state)}")
        verdict: Verdict | None = None
        origin = "default"
        for lr in self.policy.rules:
            if lr.origin != "self_protect" and budget_verdict is not None:
                break
            if lr.compiled.matches(f, new_state):
                verdict = Verdict(
                    action=Action.parse(lr.rule.action),
                    rule_id=lr.rule.id,
                    reason=lr.rule.reason,
                    decided_by="rules",
                )
                origin = lr.origin
                break
        if budget_verdict is not None and (verdict is None or verdict.action < Action.DENY):
            verdict, origin = budget_verdict, "budget"
        if verdict is None:
            verdict = self._default(f)
        if self.decider is not None:
            verdict, note = apply_decider(self.decider, event, verdict)
            if note:
                notes.append(note)
        if caps is not None:
            if verdict.action is Action.ASK and not caps.can_ask:
                verdict = Verdict(
                    action=Action.DENY,
                    rule_id=verdict.rule_id,
                    reason=f"{verdict.reason} (adapter cannot ask a human; denied)",
                    decided_by=verdict.decided_by,
                )
                notes.append("ask_downgraded_to_deny: adapter cannot ask")
            if not caps.can_block:
                notes.append("adapter_cannot_block: verdict is advisory only")
        return Decision(verdict, notes, new_state, origin)
