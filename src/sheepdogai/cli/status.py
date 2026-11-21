"""``sheepdog status``."""

from __future__ import annotations

import os
from pathlib import Path

from sheepdogai.constants import CLI_NAME, CONFIG_FILE
from sheepdogai.core.errors import SheepdogError
from sheepdogai.daemon.client import sock_for


def cmd_status(project: Path, home: Path) -> int:
    """Print policy validity, daemon state and installed hooks."""
    from sheepdogai.cli.install import SPECS, state_dir
    from sheepdogai.policy.loader import load_policy

    rules = project / CONFIG_FILE
    pol = None
    print(f"project: {project}")
    try:
        pol = load_policy(rules if rules.exists() else None, project_root=project)
        src = rules if rules.exists() else "built-in defaults (no sheepdog.yaml)"
        print(
            f"policy:  OK mode={pol.config.mode} hash={pol.policy_hash[:16]} rules={len(pol.rules)} from {src}"
        )
    except SheepdogError as e:
        print(f"policy:  INVALID: {e}")
        print("         (the daemon denies every call until this is fixed)")
    from sheepdogai.policy.loader import shared_state

    ap = pol.config.approvals if pol is not None else None
    if (
        ap is not None
        and ap.channel != "cli"
        and float(os.environ.get("SHEEPDOG_TIMEOUT_S", "5")) <= ap.ask_timeout_s
    ):
        print(
            f"warning: approvals.channel={ap.channel} needs SHEEPDOG_TIMEOUT_S > {ap.ask_timeout_s} "
            "or the hook times out (and denies) before you can answer"
        )

    state, h = shared_state(project)
    if state != "absent":
        print(
            f"shared:  .sheepdog/shared.yaml sha256 {str(h)[:16]} is {state}"
            + ("" if state == "approved" else f" (review it, then `{CLI_NAME} approve-shared`)")
        )
    s = sock_for(str(project))
    print(
        f"daemon:  {'running' if os.path.exists(s) else 'not running (starts on first hook call)'}"
    )
    for cli in SPECS:
        for scope in ("project", "user"):
            if (state_dir(scope, project, home) / f"{cli}-{scope}.json").exists():
                print(f"hook:    {cli} installed ({scope})")
    runs = (
        sorted((project / ".sheepdog" / "runs").glob("*.jsonl"))
        if (project / ".sheepdog" / "runs").exists()
        else []
    )
    print(f"runs:    {len(runs)} recorded; verify with `{CLI_NAME} verify-log <run>`")
    return 0
