from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_fuzz_target_smoke_runs_without_atheris() -> None:
    r = subprocess.run(
        [sys.executable, "fuzz/fuzz_policy.py", "--smoke"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": f"{ROOT}/src:{ROOT}", "PATH": "/usr/bin:/bin"},
        check=False,
    )
    assert r.returncode == 0 and "smoke ok" in r.stdout, r.stderr
