"""Repo hygiene gate: forbidden constructs, network imports in core, UNVERIFIED placement."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = [r"\beval\(", r"\bexec\(", r"\bpickle\b", r"(?<!\w)shell\s*=\s*True", r"yaml\.load\("]
NET_DIRS = ["core", "policy", "log", "redact"]
NET_RE = re.compile(r"^\s*(import|from)\s+(socket|urllib|http)\b", re.M)
# UNVERIFIED may appear only in experimental adapters, docs, tests and this tooling.
UNVERIFIED_OK = (
    "src/sheepdogai/adapters/codex.py",
    "src/sheepdogai/adapters/mcp_proxy.py",
    "src/sheepdogai/adapters/wrap.py",
    "docs/",
    "tests/",
    "tools/",
    "src/sheepdogai/adapters/_fixtures/",
    "CHANGELOG.md",
    "README.md",
    ".pre-commit-config.yaml",
    "Makefile",
)


def main() -> int:
    errs: list[str] = []
    for p in (ROOT / "src").rglob("*.py"):
        t = p.read_text()
        rel = p.relative_to(ROOT).as_posix()
        for pat in FORBIDDEN:
            if re.search(pat, t):
                errs.append(f"{rel}: forbidden pattern {pat}")
        if p.relative_to(ROOT / "src/sheepdogai").parts[0] in NET_DIRS and NET_RE.search(t):
            errs.append(f"{rel}: network import in no-network package")
    for p in ROOT.rglob("*"):
        if not p.is_file() or ".venv" in p.parts or ".git" in p.parts or p.suffix in {".lock"}:
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel.startswith(UNVERIFIED_OK):
            continue
        try:
            if "UNVERIFIED" in p.read_text():
                errs.append(f"{rel}: UNVERIFIED outside experimental adapters")
        except (UnicodeDecodeError, OSError):
            continue
    for e in errs:
        print(e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
