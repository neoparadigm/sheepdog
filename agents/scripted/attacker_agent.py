"""Scripted attacker: an untrusted-content marker followed by a harmful call, plus obfuscated
variants from the fuzz generators. No model, no network."""

from __future__ import annotations

from dataclasses import dataclass

from agents.scripted import obfuscate
from agents.scripted.benign_agent import Step


@dataclass(frozen=True)
class AttackScenario:
    """The minimal shape the attacker needs."""

    id: str
    steps: list[Step]
    untrusted_source: str | None = None  # URL the agent "read" before the harmful call
    obfuscate: list[str] | None = None


class AttackerAgent:
    """Emits the (setup, harm) step sequence for a scenario and its obfuscated variants."""

    def __init__(self, scenario: AttackScenario) -> None:
        self.s = scenario

    def sequence(self, harm: Step | None = None) -> list[Step]:
        """Setup step (reading untrusted content) then the harmful step(s)."""
        out: list[Step] = []
        if self.s.untrusted_source:
            out.append(Step("fetch", {"url": self.s.untrusted_source}, role="setup"))
        out.extend(self.s.steps if harm is None else [harm])
        return out

    def variants(self) -> list[tuple[str, list[Step]]]:
        """(label, steps) for the plain scenario and each applicable obfuscation of bash steps."""
        base = [s if s.role != "benign" else Step(s.tool, s.args, "harm") for s in self.s.steps]
        pre: list[Step] = (
            [Step("fetch", {"url": self.s.untrusted_source}, role="setup")]
            if self.s.untrusted_source
            else []
        )
        out = [("plain", pre + base)]
        if not self.s.obfuscate:
            return out
        names = (
            list(obfuscate.ALL)
            if self.s.obfuscate == ["all"]
            else (obfuscate.CORE if self.s.obfuscate == ["core"] else self.s.obfuscate)
        )
        last = base[-1]
        if last.tool == "bash":
            for name, cmd in obfuscate.variants(str(last.args["command"]), names):
                out.append((name, pre + [*base[:-1], Step("bash", {"command": cmd}, "harm")]))
        return out
