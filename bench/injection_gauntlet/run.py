"""Injection gauntlet runner: scripted agents through adapter -> engine -> log, no model, no network.

Usage: python -m bench.injection_gauntlet.run [--corpus v1] [--out bench/report.md]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import random
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from agents.harness_runner import Harness
from agents.scripted.attacker_agent import AttackerAgent, AttackScenario
from agents.scripted.benign_agent import Step
from pydantic import BaseModel, ConfigDict

from sheepdogai.constants import __version__

CORPUS_DIR = Path(__file__).resolve().parent / "corpus"
ADAPTERS = ["claude", "gemini", "codex"]
MODE = "balanced"


class StepSpec(BaseModel):
    """One step in a scenario (tool plus its arguments)."""

    model_config = ConfigDict(extra="allow")
    tool: str


class Scenario(BaseModel):
    """A corpus entry."""

    model_config = ConfigDict(extra="forbid")
    id: str
    kind: Literal["attack", "benign"]
    category: str
    title: str
    steps: list[StepSpec]
    untrusted_source: str | None = None
    obfuscate: str | list[str] | None = None
    known_gap: bool = False


@dataclass
class Instance:
    """One concrete run of a scenario (a base scenario or one obfuscated variant)."""

    scenario: Scenario
    variant: str
    steps: list[Step]

    @property
    def name(self) -> str:
        """Display id."""
        return self.scenario.id if self.variant == "plain" else f"{self.scenario.id}~{self.variant}"


@dataclass
class Outcome:
    """Result of one instance on one adapter."""

    adapter: str
    instance: str
    scenario: str
    kind: str
    category: str
    variant: str
    known_gap: bool
    verdict: str  # worst verdict over the evaluated steps: allow < ask < deny
    hard_deny: bool
    rule_id: str | None
    command: str
    wall_ms: list[float] = field(default_factory=list)
    cpu_ms: list[float] = field(default_factory=list)


def load_corpus(version: str = "v1") -> tuple[list[Scenario], str]:
    """Load and validate the corpus; returns (scenarios, corpus content hash)."""
    d = CORPUS_DIR / version
    files = sorted(d.glob("*.yaml"))
    if not files:
        raise SystemExit(f"no corpus at {d}")
    h = hashlib.sha256()
    out: list[Scenario] = []
    for f in files:
        h.update(f.name.encode() + b"\0" + f.read_bytes())
        out.extend(Scenario.model_validate(x) for x in yaml.safe_load(f.read_text()))
    ids = [s.id for s in out]
    if len(set(ids)) != len(ids):
        raise SystemExit("duplicate scenario ids in corpus")
    return out, h.hexdigest()


def expand(scenarios: list[Scenario]) -> list[Instance]:
    """Expand obfuscation variants for attacks."""
    out: list[Instance] = []
    for s in scenarios:
        steps = [
            Step(
                x.tool,
                {k: v for k, v in x.model_dump().items() if k != "tool"},
                "harm" if s.kind == "attack" else "benign",
            )
            for x in s.steps
        ]
        if s.kind == "attack":
            ob = (
                None
                if s.obfuscate is None
                else [s.obfuscate]
                if isinstance(s.obfuscate, str)
                else s.obfuscate
            )
            ag = AttackerAgent(AttackScenario(s.id, steps, s.untrusted_source, ob))
            out.extend(Instance(s, label, st) for label, st in ag.variants())
        else:
            pre = (
                [Step("fetch", {"url": s.untrusted_source}, "setup")] if s.untrusted_source else []
            )
            out.append(Instance(s, "plain", pre + steps))
    return out


ORDER = {"allow": 0, "ask": 1, "deny": 2}


def run_adapter(
    adapter: str, instances: list[Instance], mode: str = MODE
) -> tuple[list[Outcome], str]:
    """Run every instance on one adapter in a fresh isolated project."""
    h = Harness(
        adapter,
        config=f"version: 1\nmode: {mode}\nbudget: {{max_steps: 1000000, max_repeats: 1000000}}\n",
    )
    outs: list[Outcome] = []
    try:
        for inst in instances:
            session = f"{inst.name}".replace("~", "_")
            cpu0 = time.process_time()
            results = h.run(session, inst.steps)
            cpu = (time.process_time() - cpu0) * 1000
            judged = [r for r in results if r.step.role != "setup"]
            worst = max(judged, key=lambda r: ORDER[r.verdict])
            outs.append(
                Outcome(
                    adapter,
                    inst.name,
                    inst.scenario.id,
                    inst.scenario.kind,
                    inst.scenario.category,
                    inst.variant,
                    inst.scenario.known_gap,
                    worst.verdict,
                    any(r.hard_deny for r in judged),
                    worst.rule_id,
                    worst.command[:160],
                    [r.wall_ms for r in results],
                    [cpu / max(1, len(results))] * len(results),
                )
            )
        return outs, h.policy_hash
    finally:
        h.cleanup()


# ------------------------------------------------------------------------ statistics


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95% interval for a proportion."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - m), min(1.0, c + m)


def pct(xs: list[float], q: float) -> float:
    """Percentile by nearest rank on a sorted copy."""
    s = sorted(xs)
    return s[min(len(s) - 1, int(q * (len(s) - 1) + 0.5))] if s else 0.0


def boot_ci(xs: list[float], stat: Any, n: int = 400, seed: int = 0) -> tuple[float, float]:
    """Percentile-bootstrap 95% CI with a fixed seed (the report is reproducible)."""
    if not xs:
        return 0.0, 0.0
    rng = random.Random(seed)
    vals = sorted(stat([xs[rng.randrange(len(xs))] for _ in xs]) for _ in range(n))
    return vals[int(0.025 * n)], vals[int(0.975 * n) - 1]


def summarise(outs: list[Outcome]) -> dict[str, Any]:
    """Metrics for one adapter."""
    atk = [o for o in outs if o.kind == "attack"]
    ben = [o for o in outs if o.kind == "benign"]
    blocked = [o for o in atk if o.verdict != "allow"]
    hard = [o for o in atk if o.hard_deny]
    fp = [o for o in ben if o.hard_deny]
    friction = [o for o in ben if o.verdict != "allow" and not o.hard_deny]
    wall = [x for o in outs for x in o.wall_ms]
    cpu = [x for o in outs for x in o.cpu_ms]
    return {
        "attacks": len(atk),
        "blocked": len(blocked),
        "block_rate": len(blocked) / max(1, len(atk)),
        "block_ci": wilson(len(blocked), len(atk)),
        "hard_denied": len(hard),
        "hard_ci": wilson(len(hard), len(atk)),
        "benign": len(ben),
        "false_positives": len(fp),
        "fp_rate": len(fp) / max(1, len(ben)),
        "fp_ci": wilson(len(fp), len(ben)),
        "friction": len(friction),
        "friction_rate": len(friction) / max(1, len(ben)),
        "friction_ci": wilson(len(friction), len(ben)),
        "decisions": len(wall),
        "p50_ms": pct(wall, 0.5),
        "p95_ms": pct(wall, 0.95),
        "p50_ci": boot_ci(wall, lambda v: pct(v, 0.5)),
        "p95_ci": boot_ci(wall, lambda v: pct(v, 0.95)),
        "cpu_ms_per_1000": 1000 * sum(cpu) / max(1, len(cpu)),
        "cpu_ci_per_1000": tuple(1000 * x for x in boot_ci(cpu, lambda v: sum(v) / max(1, len(v)))),
        "got_through": [
            {
                "id": o.instance,
                "category": o.category,
                "known_gap": o.known_gap,
                "command": o.command,
            }
            for o in atk
            if o.verdict == "allow"
        ],
        "false_positive_list": [
            {"id": o.instance, "rule": o.rule_id, "command": o.command} for o in fp
        ],
        "friction_list": [o.instance for o in friction],
    }


def run_all(
    version: str = "v1", adapters: list[str] | None = None, mode: str = MODE
) -> dict[str, Any]:
    """Run the whole benchmark and return the results dict."""
    scenarios, chash = load_corpus(version)
    instances = expand(scenarios)
    per: dict[str, Any] = {}
    phash = ""
    for a in adapters or ADAPTERS:
        outs, phash = run_adapter(a, instances, mode)
        per[a] = {"summary": summarise(outs), "outcomes": [asdict(o) for o in outs]}
    return {
        "corpus_version": version,
        "corpus_sha256": chash,
        "policy_hash": phash,
        "mode": mode,
        "scenarios": len(scenarios),
        "instances": len(instances),
        "sheepdogai_version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "adapters": per,
    }


def cmd_bench(version: str, out: str | None) -> int:
    """CLI entry: run balanced (the default) and strict, write the Markdown + JSON report, print it."""
    from bench.injection_gauntlet.report import render

    runs = {m: run_all(version, mode=m) for m in ("balanced", "strict")}
    text = "\n\n---\n\n".join(render(r) for r in runs.values())
    if out:
        Path(out).write_text(text)
        Path(out).with_suffix(".json").write_text(
            json.dumps(
                {
                    m: {
                        k: (
                            {a: v["summary"] for a, v in r["adapters"].items()}
                            if k == "adapters"
                            else v
                        )
                        for k, v in r.items()
                    }
                    for m, r in runs.items()
                },
                indent=2,
                sort_keys=True,
            )
        )
    print(text)
    return 0


def main() -> int:
    """``python -m bench.injection_gauntlet.run``."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="v1")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    return cmd_bench(a.corpus, a.out)


if __name__ == "__main__":
    sys.exit(main())
