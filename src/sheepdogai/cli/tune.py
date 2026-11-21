"""``sheepdogai mode|allow|block``: change the active policy from the command line or from chat.

The agent can run these (that is the point of ``/sheepdogai``), but ``self_protect`` makes every one of
them ask the human first, so an agent cannot loosen its own guard unattended.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from sheepdogai.cli.setup import USER_CONFIG_TEMPLATE, user_config_path
from sheepdogai.constants import CLI_NAME, CONFIG_FILE
from sheepdogai.core.errors import SheepdogError
from sheepdogai.policy.loader import load_policy

MODES = ("strict", "balanced", "relaxed")


def active_config(project: Path, home: Path) -> Path:
    """The file that governs this project: its own sheepdogai.yaml, else the user-wide one (created)."""
    p = project / CONFIG_FILE
    if p.exists():
        return p
    u = user_config_path(home)
    if not u.exists():
        u.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(u, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(
            fd,
            USER_CONFIG_TEMPLATE.format(cli=CLI_NAME, config=CONFIG_FILE, mode="balanced").encode(),
        )
        os.close(fd)
    return u


def _write_checked(path: Path, new: str, project: Path, home: Path) -> None:
    """Write ``new`` only if the result is a valid policy; otherwise restore and raise."""
    old = path.read_text()
    path.write_text(new)
    try:
        load_policy(path, project_root=project, home=str(home))
    except SheepdogError:
        path.write_text(old)
        raise


def set_mode(project: Path, home: Path, mode: str) -> str:
    """Set ``mode:`` (keeps comments). Returns a plain-language summary."""
    path = active_config(project, home)
    text = path.read_text()
    line = re.compile(r"^mode:.*$", re.M)
    new = (
        line.sub(f"mode: {mode}", text, count=1)
        if line.search(text)
        else text.replace("version: 1", f"version: 1\nmode: {mode}", 1)
    )
    _write_checked(path, new, project, home)
    meaning = {
        "strict": "asks before anything not covered by a rule",
        "balanced": "lets read-only commands run and checks the rest",
        "relaxed": "only blocks what the safety rules forbid",
    }[mode]
    return f"Mode is now {mode}: {meaning}.  ({path})"


def add_rule(project: Path, home: Path, pattern: str, action: str) -> str:
    """Append an allow/deny rule for a command glob to the active config."""
    if not pattern.strip() or re.fullmatch(r"[\s*?]*", pattern):
        raise SheepdogError(
            "refusing a pattern that matches everything; name the command, e.g. 'git status*'"
        )
    path = active_config(project, home)
    text = path.read_text()
    n = 1
    while f"user-{action}-{n}" in text:
        n += 1
    rid = f"user-{action}-{n}"
    item = (
        f"  - id: {rid}\n    match: {{tool: [Bash, run_shell_command], command: {_q(pattern)}}}\n"
        f"    action: {action}\n    reason: added with `{CLI_NAME} {'allow' if action == 'allow' else 'block'}`\n"
    )
    lines = text.splitlines(keepends=True)
    idx = next(
        (i for i, ln in enumerate(lines) if re.match(r"^rules:\s*(\[\])?\s*(#.*)?$", ln)), None
    )
    if idx is None:
        new = text.rstrip("\n") + "\n\nrules:\n" + item
    else:
        end = idx + 1
        while end < len(lines) and (
            lines[end].startswith((" ", "\t", "#")) or not lines[end].strip()
        ):
            end += 1
        head = "rules:\n" if lines[idx].strip().startswith("rules:") else lines[idx]
        new = (
            "".join(lines[:idx])
            + head
            + "".join(lines[idx + 1 : end]).rstrip("\n")
            + ("\n" if end > idx + 1 else "")
            + item
            + "".join(lines[end:])
        )
    _write_checked(path, new, project, home)
    note = (
        "  Note: your rules run before the built-in safety packs, so this can override them."
        if action == "allow"
        else ""
    )
    return f"Rule {rid}: {action} commands matching {pattern!r}.  ({path}){note}"


def _q(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
