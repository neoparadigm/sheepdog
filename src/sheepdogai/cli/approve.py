"""``sheepdog approve-shared``: the human approves the hash of the committed shared config."""

from __future__ import annotations

import sys
from pathlib import Path

from sheepdogai.core.errors import RulesError
from sheepdogai.policy.loader import (
    APPROVED_REL,
    SHARED_REL,
    approve_shared,
    load_user_config,
    parse_shared,
    shared_state,
    validate_shared,
)


def cmd_approve_shared(project: Path, yes: bool, revoke: bool) -> int:
    """Show what the shared config would change, ask, and record the approved hash."""
    ap = project / APPROVED_REL
    if revoke:
        if ap.exists():
            ap.unlink()
        print("approval revoked; the shared config is ignored again")
        return 0
    state, h = shared_state(project)
    if state == "absent":
        print(f"no {SHARED_REL} in {project}", file=sys.stderr)
        return 1
    cfg, lines = parse_shared(project / SHARED_REL)
    try:
        validate_shared(cfg, load_user_config(project), lines)
    except RulesError as e:
        print(f"refusing to approve: {e}", file=sys.stderr)
        return 1
    print(f"{SHARED_REL}  sha256 {h}")
    print(
        f"  mode: {cfg.mode or '(unchanged)'}   extra packs: {cfg.packs or 'none'}   "
        f"budget: {cfg.budget.model_dump() if cfg.budget else '(unchanged)'}"
    )
    for r in cfg.rules:
        print(f"  rule shared.{r.id}: {r.action}  {r.reason}")
    if state == "approved":
        print("already approved")
        return 0
    if not yes:
        if not sys.stdin.isatty():
            print("not a terminal: pass --yes to approve non-interactively", file=sys.stderr)
            return 1
        if input("Approve this exact file? [y/N] ").strip().lower() != "y":
            print("not approved")
            return 1
    approve_shared(project)
    print("approved; a changed file needs approval again")
    return 0
