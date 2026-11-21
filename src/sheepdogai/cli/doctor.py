"""``sheepdogai doctor`` and ``sheepdogai recent``: plain-language answers to "is it working?"."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from sheepdogai.constants import CLI_NAME
from sheepdogai.core.errors import SheepdogError

OK, BAD = "OK  ", "FAIL"


def _hook_installed(cli: str, home: Path, project: Path) -> tuple[str, str] | None:
    """(where, command) of our hook entry, or None."""
    from sheepdogai.cli.install import SPECS, is_our_command, target_path

    spec = SPECS[cli]
    for scope in ("user", "project"):
        p = target_path(cli, scope, project, home)
        try:
            data = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        for entry in data.get("hooks", {}).get(spec["event"], []):
            for h in entry.get("hooks", []):
                if is_our_command(h.get("command"), cli):
                    return f"{scope} ({p})", str(h["command"])
    return None


def _program_exists(command: str) -> bool:
    """Does the program the hook runs exist and can it be executed?"""
    import os
    import shlex

    try:
        first = shlex.split(command)[0]
    except (ValueError, IndexError):
        return False
    if os.sep in first:
        return os.access(first, os.X_OK)
    return shutil.which(first) is not None


def cmd_doctor(project: Path, home: Path) -> int:
    """Run the checks and print one line each with a fix. Returns 0 only if all pass."""
    from sheepdogai.cli.setup import detect, self_test
    from sheepdogai.log.verify import verify_log
    from sheepdogai.policy.loader import find_rules, load_policy

    bad = 0

    def line(ok: bool, msg: str, fix: str = "") -> None:
        nonlocal bad
        bad += 0 if ok else 1
        print(f"[{OK if ok else BAD}] {msg}" + (f"\n        fix: {fix}" if fix and not ok else ""))

    line(
        shutil.which(CLI_NAME) is not None,
        f"the `{CLI_NAME}` command is installed and on your PATH",
        "run: uv tool install sheepdogai   (then open a new terminal)",
    )
    agents = detect(home)
    line(
        bool(agents),
        "an AI agent was found on this computer (Claude Code or Gemini CLI)",
        "install Claude Code or Gemini CLI first",
    )
    for cli in agents:
        found = _hook_installed(cli, home, project)
        line(
            found is not None,
            f"{cli}: protection is switched on" + (f" via {found[0]}" if found else ""),
            f"run: {CLI_NAME} setup",
        )
        if found:
            line(
                _program_exists(found[1]),
                f"{cli}: the program the hook runs exists (an agent skips a hook that cannot start)",
                f"run: {CLI_NAME} setup   (it was probably moved or uninstalled)",
            )
    from sheepdogai.cli.skills import skill_targets

    for cli in agents:
        ts = skill_targets(home).get(cli)
        if ts:
            line(
                any(p.exists() for p, _c in ts),
                f"{cli}: you can type /sheepdog to chat with it",
                f"run: {CLI_NAME} setup",
            )
    path = find_rules(project)
    try:
        pol = load_policy(path, project_root=project)
        line(True, f"your rules are valid ({pol.config.mode} mode, {len(pol.rules)} rules)")
    except SheepdogError as e:
        line(
            False,
            f"your rules file has a mistake: {e}",
            f"edit {path} or delete it and run: {CLI_NAME} setup",
        )
    ok, msg = self_test(home)
    line(
        ok,
        "a dangerous test command was blocked (this tests the real hook end to end)"
        + ("" if ok else f": {msg}"),
        f"run: {CLI_NAME} setup, then {CLI_NAME} doctor again",
    )
    runs = (
        sorted((project / ".sheepdogai" / "runs").glob("*.jsonl"))
        if (project / ".sheepdogai" / "runs").exists()
        else []
    )
    if runs:
        broken = [r.name for r in runs if not verify_log(r).ok]
        line(
            not broken,
            f"the activity log in this folder is intact ({len(runs)} sessions)"
            if not broken
            else f"the activity log was changed or damaged: {', '.join(broken)}",
            "",
        )
    print()
    if bad == 0:
        print(
            "Everything looks good. To see for yourself, ask your agent to run `sudo whoami`: it will be refused."
        )
        print(f"See what was blocked or questioned: {CLI_NAME} recent")
    else:
        print(f"{bad} problem(s) found. Follow the 'fix' lines above.")
    return 0 if bad == 0 else 1


def cmd_recent(project: Path, n: int) -> int:
    """Show the last ``n`` decisions in this folder in plain language."""
    runs = project / ".sheepdogai" / "runs"
    rows: list[tuple[str, str, str, str]] = []
    for f in sorted(runs.glob("*.jsonl")) if runs.exists() else []:
        for ln in f.read_text().splitlines():
            r = json.loads(ln)
            if r["kind"] != "decision":
                continue
            d = r["data"]
            ev, v = d["event"], d["verdict"]
            a = ev["args"]
            what = str(
                a.get("command") or a.get("path") or a.get("url") or ev["tool"]["name"]
            ).replace("\n", " ")[:70]
            rows.append((ev["ts"], v["action"], what, v.get("reason") or ""))
    if not rows:
        print("Nothing recorded in this folder yet. Use your agent here, then run this again.")
        return 0
    label = {"deny": "BLOCKED  ", "ask": "ASKED    ", "allow": "allowed  "}
    for ts, act, what, why in sorted(rows)[-n:]:
        print(
            f"{ts[11:19]}  {label[act]} {what}"
            + (f"\n                      why: {why}" if act != "allow" and why else "")
        )
    return 0
