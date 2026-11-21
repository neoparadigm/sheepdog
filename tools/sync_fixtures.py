"""Mirror tests/fixtures into the package (adapters/_fixtures) used by scripted agents."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tests" / "fixtures"
DST = ROOT / "src" / "sheepdogai" / "adapters" / "_fixtures"


def main() -> int:
    check = "--check" in sys.argv
    bad = False
    for f in sorted(SRC.rglob("*.json")):
        t = DST / f.relative_to(SRC)
        if check:
            if not t.exists() or t.read_bytes() != f.read_bytes():
                print("out of sync:", t)
                bad = True
        else:
            t.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, t)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
