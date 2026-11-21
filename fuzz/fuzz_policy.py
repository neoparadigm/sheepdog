"""Coverage-guided fuzz target (Atheris) for ClusterFuzzLite: the shell normaliser and the engine.

Properties checked on arbitrary bytes: nothing raises, and a command that normalises to a dangerous
recursive delete is never allowed. Also runnable without Atheris: ``python fuzz/fuzz_policy.py``.
"""

from __future__ import annotations

import sys
from pathlib import Path

from sheepdogai.core.verdict import Action
from sheepdogai.policy.engine import PolicyEngine
from sheepdogai.policy.loader import load_policy
from sheepdogai.policy.matchers import parse_shell

_ENGINE = PolicyEngine(load_policy(None, project_root=Path("/work/proj"), home="/home/fuzz"))


def check(data: bytes) -> None:
    """One fuzz iteration; raises AssertionError on a safety violation."""
    from tests.helpers import event

    cmd = data.decode("utf-8", errors="replace")
    parsed = parse_shell(cmd)
    verdict = _ENGINE.decide(event(cmd, cwd="/work/proj")).verdict
    assert verdict.action in (Action.ALLOW, Action.ASK, Action.DENY)
    flat = [s.flat for s in parsed.segments]
    if any(f in {"rm -r -f /", "rm -r -f ~"} for f in flat):
        assert verdict.action is not Action.ALLOW, cmd


def main() -> None:
    """Entry point used by ClusterFuzzLite (needs ``atheris``)."""
    import atheris

    atheris.Setup(sys.argv, check)
    atheris.Fuzz()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--smoke":
        for sample in (b"rm -rf /", b"$(echo rm) -rf /", b"\xff\xfe", b"a" * 5000):
            check(sample)
        print("smoke ok")
    else:
        main()
