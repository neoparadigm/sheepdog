"""Push a scripted agent through adapter -> engine -> log -> graph, in process.

Used by ``sheepdogai bench`` and the red-team suite. A fresh temp project (with a real symlink and
an "outside" directory) is created per harness so path-escape scenarios are real.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agents.scripted.benign_agent import Step, payload_for
from sheepdogai.core.verdict import Action
from sheepdogai.daemon.server import Gateway

ADAPTERS = {"claude": "claude", "gemini": "gemini", "codex": "codex"}


@dataclass
class StepResult:
    """What happened to one step."""

    step: Step
    verdict: str  # allow | ask | deny
    hard_deny: bool  # deny that was not an ask downgraded by a CLI that cannot ask
    rule_id: str | None
    wall_ms: float
    command: str


@dataclass
class Harness:
    """An isolated project + gateway for one adapter."""

    adapter: str
    config: str = "version: 1\nmode: balanced\nbudget: {max_steps: 100000, max_repeats: 100000}\n"
    root: Path = field(init=False)
    project: Path = field(init=False)
    home: Path = field(init=False)
    outside: Path = field(init=False)
    gw: Gateway = field(init=False)

    def __post_init__(self) -> None:
        base = Path(__file__).resolve().parent.parent / "bench" / ".work"
        base.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix=f"{self.adapter}-", dir=base))
        self.project = self.root / "proj"
        self.home = self.root / "home"
        self.outside = self.root / "outside"
        for d in (self.project / "src", self.home / ".ssh", self.home / ".aws", self.outside):
            d.mkdir(parents=True)
        (self.project / "link").symlink_to(self.outside)
        (self.project / "sheepdogai.yaml").write_text(self.config)
        self.gw = Gateway(self.project, home=str(self.home))

    def subst(self, v: Any) -> Any:
        """Replace {project}, {home}, {outside} placeholders."""
        if isinstance(v, str):
            return (
                v.replace("{project}", str(self.project))
                .replace("{home}", str(self.home))
                .replace("{outside}", str(self.outside))
            )
        if isinstance(v, dict):
            return {k: self.subst(x) for k, x in v.items()}
        if isinstance(v, list):
            return [self.subst(x) for x in v]
        return v

    @property
    def policy_hash(self) -> str:
        """Hash of the policy in force."""
        return self.gw.policy.policy_hash

    def run(self, session: str, steps: list[Step]) -> list[StepResult]:
        """Send each step through the full pipeline and classify the response."""
        out: list[StepResult] = []
        for st in steps:
            st = Step(st.tool, self.subst(st.args), st.role)
            raw = payload_for(self.adapter, st, session, str(self.project))
            t = time.perf_counter()
            resp = self.gw.handle(self.adapter, raw, experimental=True)
            wall = (time.perf_counter() - t) * 1000
            dec = self.gw.last_decision
            assert dec is not None
            downgraded = any(n.startswith("ask_downgraded") for n in dec.notes)
            if resp.exit_code == 2:
                verdict = "deny"
            elif resp.stdout and '"ask"' in resp.stdout:
                verdict = "ask"
            else:
                verdict = "allow"
            hard = dec.verdict.action is Action.DENY and not downgraded
            out.append(
                StepResult(
                    st,
                    verdict,
                    hard,
                    dec.verdict.rule_id,
                    wall,
                    str(st.args.get("command") or st.args.get("path") or st.args.get("url") or ""),
                )
            )
        return out

    def log_path(self, session: str) -> Path:
        """Path of the hash-chained log for a session."""
        return self.project / ".sheepdogai" / "runs" / f"{session}.jsonl"

    def graph_mermaid(self, session: str) -> str:
        """Run graph (Mermaid) for a session, from the log."""
        from sheepdogai.graph.builder import graph_from_log
        from sheepdogai.graph.export_mermaid import export_mermaid

        self.gw.close()
        return export_mermaid(graph_from_log(self.log_path(session)))

    def records(self, session: str) -> list[dict[str, Any]]:
        """Parsed log records."""
        self.gw.close()
        return [json.loads(x) for x in self.log_path(session).read_text().splitlines()]

    def cleanup(self) -> None:
        """Close and delete the temp project."""
        self.gw.close()
        shutil.rmtree(self.root, ignore_errors=True)
