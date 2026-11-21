"""Fail if any required test suite folder is missing or contains no test."""
from __future__ import annotations

import sys
from pathlib import Path

REQUIRED = ["unit", "property", "fuzz", "conformance", "redteam", "replay",
            "ontology", "perf", "unit/log", "unit/self_protect"]


def main() -> int:
    root = Path(__file__).resolve().parent.parent / "tests"
    bad = []
    for name in REQUIRED:
        d = root / name
        n = sum(1 for p in d.glob("test_*.py")) if d.is_dir() else 0
        if n == 0:
            bad.append(name)
    if bad:
        print("missing or empty test suites:", ", ".join(bad))
        return 1
    print("all required suites present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
