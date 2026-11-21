"""Verdicts, budget state and decision records."""

from __future__ import annotations

from enum import IntEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, field_serializer, field_validator

from sheepdogai.core.events import ToolCallEvent


class Action(IntEnum):
    """Strictness-ordered actions: allow < ask < deny."""

    ALLOW = 0
    ASK = 1
    DENY = 2

    @property
    def label(self) -> Literal["allow", "ask", "deny"]:
        """Lower-case wire name."""
        return ("allow", "ask", "deny")[self.value]

    @classmethod
    def parse(cls, s: str) -> Action:
        """Parse ``allow|ask|deny`` (case-insensitive); raises ValueError otherwise."""
        try:
            return cls[s.strip().upper()]
        except KeyError as e:
            raise ValueError(f"unknown action {s!r}") from e


class Verdict(BaseModel):
    """A decision about one tool call."""

    model_config = ConfigDict(frozen=True)

    action: Action
    rule_id: str | None = None
    reason: str = ""
    decided_by: str = "rules"

    @field_validator("action", mode="before")
    @classmethod
    def _parse_action(cls, v: object) -> object:
        return Action.parse(v) if isinstance(v, str) else v

    @field_serializer("action")
    def _ser_action(self, a: Action) -> str:
        return a.label

    def stricter_than_or_equal(self, other: Verdict) -> bool:
        """True when this verdict is at least as strict as ``other``."""
        return self.action >= other.action


def deny(reason: str, rule_id: str | None = None, decided_by: str = "engine") -> Verdict:
    """Build a deny verdict."""
    return Verdict(action=Action.DENY, rule_id=rule_id, reason=reason, decided_by=decided_by)


class BudgetState(BaseModel):
    """Running budget counters for one run."""

    model_config = ConfigDict(frozen=True)

    steps: int = 0
    cost_usd: float = 0.0
    cost_known: bool = False
    repeats: int = 0
    last_fingerprint: str | None = None
    last_failed: bool | None = None
    exceeded: str | None = None


class DecisionRecord(BaseModel):
    """What the log stores per decision."""

    model_config = ConfigDict(frozen=True)

    event: ToolCallEvent
    verdict: Verdict
    latency_ms: float
    policy_hash: str
    notes: list[str] = []
    budget: BudgetState | None = None
    rules_verdict: Verdict | None = None  # set when a Decider ran: what the rules said
    decider_proposed: Verdict | None = None  # set when a Decider ran: its raw answer
