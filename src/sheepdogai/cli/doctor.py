"""``sheepdog doctor`` and ``sheepdog recent``: plain-language answers to "is it working?"."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from sheepdogai.constants import CLI_NAME, CONFIG_FILE
from sheepdogai.core.errors import SheepdogError

OK, BAD = "OK  ", "FAIL"


def _hook_installed(cli: str, home: Path, project: Path) -> str | None:
    from sheepdogai.cli.install import SPECS, target_path

    spec = SPECS[cli]
    for scope, base in (("user", home), ("project", project)):
        p = target_path(cli, scope, project, home)
        try:
            data = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        for entry in data.get("hooks", {}).get(spec["event"], []):
            if any(h.get("command") == spec["cmd"] for h in entry.get("hooks", [])):
                return f"{scope} ({p})"
        del base
    return None


def cmd_doctor(project: Path, home: Path) -> int:
    """Run the checks and print one line each with a fix. Returns 0 only if all pass."""
    from sheepdogai.cli.setup import detect, self_test, user_config_path
    from sheepdogai.log.verify import verify_log
    from sheepdogai.policy.loader import load_policy

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
        where = _hook_installed(cli, home, project)
        line(
            where is not None,
            f"{cli}: protection is switched on" + (f" via {where}" if where else ""),
            f"run: {CLI_NAME} setup",
        )
    rules = project / CONFIG_FILE
    path = (
        rules
        if rules.exists()
        else (user_config_path(home) if user_config_path(home).exists() else None)
    )
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
        sorted((project / ".sheepdog" / "runs").glob("*.jsonl"))
        if (project / ".sheepdog" / "runs").exists()
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
    runs = project / ".sheepdog" / "runs"
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
