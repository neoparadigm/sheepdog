"""``sheepdogai install|uninstall``: merge or remove our hook entry, with backup and exact undo."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import shlex
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sheepdogai.constants import CLI_NAME, PACKAGE_NAME, STATE_DIR
from sheepdogai.core.errors import SheepdogError

# claude / gemini formats are verified (see adapter docstrings). The codex layout is not verified.
SPECS: dict[str, dict[str, Any]] = {
    "claude": {
        "event": "PreToolUse",
        "matcher": "*",
        "cmd": f"{CLI_NAME} hook claude",
        "project": ".claude/settings.json",
        "user": ".claude/settings.json",
    },
    "gemini": {
        "event": "BeforeTool",
        "matcher": ".*",
        "cmd": f"{CLI_NAME} hook gemini",
        "project": ".gemini/settings.json",
        "user": ".gemini/settings.json",
    },
    "codex": {
        "event": "PreToolUse",
        "matcher": "*",
        "cmd": f"{CLI_NAME} hook codex --experimental",
        "project": ".codex/hooks.json",
        "user": ".codex/hooks.json",
    },
}


@dataclass
class Plan:
    """What an install would do."""

    path: Path
    before: bytes | None
    after: bytes
    changed: bool
    diff: str


def target_path(cli: str, scope: str, project: Path, home: Path) -> Path:
    """Config file for a CLI and scope."""
    spec = SPECS[cli]
    return Path((project if scope == "project" else home) / spec[scope])


def state_dir(scope: str, project: Path, home: Path) -> Path:
    """Where manifests and backups live (inside the self-protected state dir)."""
    return (project if scope == "project" else home) / STATE_DIR / "install"


def hook_suffix(cli: str) -> str:
    """The part of the hook command that identifies it, whatever path the program has."""
    return str(SPECS[cli]["cmd"]).split(" ", 1)[1]  # "hook claude" / "hook codex --experimental"


def hook_command(cli: str) -> str:
    """The command written into the agent's settings.

    It uses the **absolute path** of this program. A bare ``sheepdogai`` resolved through the agent's
    PATH can fail with "not found" (exit 127), which Claude Code and Gemini treat as a non-blocking error:
    the call would then run unguarded and silently. An absolute path removes that failure mode.
    """
    exe = shutil.which(CLI_NAME)
    prog = shlex.quote(exe) if exe else f"{shlex.quote(sys.executable)} -m sheepdogai.cli.main"
    return f"{prog} {hook_suffix(cli)}"


def is_our_command(command: object, cli: str) -> bool:
    """True for our hook command in any spelling (bare name, absolute path, python -m)."""
    return (
        isinstance(command, str)
        and command.endswith(" " + hook_suffix(cli))
        and (command.startswith(CLI_NAME) or PACKAGE_NAME in command)
    )


def _is_ours(entry: Any, cli: str) -> bool:
    return isinstance(entry, dict) and any(
        isinstance(h, dict) and is_our_command(h.get("command"), cli)
        for h in entry.get("hooks", [])
    )


def _dump(data: dict[str, Any]) -> bytes:
    return (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode()


def plan_install(cli: str, path: Path) -> Plan:
    """Compute the merged config without touching the disk."""
    spec = SPECS[cli]
    before: bytes | None = path.read_bytes() if path.exists() else None
    data: dict[str, Any] = {}
    if before is not None:
        try:
            loaded = json.loads(before)
        except ValueError as e:
            raise SheepdogError(f"{path} is not valid JSON; refusing to modify it: {e}") from e
        if not isinstance(loaded, dict):
            raise SheepdogError(f"{path} is not a JSON object; refusing to modify it")
        data = loaded
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise SheepdogError(f"{path}: 'hooks' is not an object")
    lst = hooks.setdefault(spec["event"], [])
    if not isinstance(lst, list):
        raise SheepdogError(f"{path}: hooks.{spec['event']} is not a list")
    if any(_is_ours(e, cli) for e in lst):
        return Plan(path, before, before or b"", False, "")
    lst.insert(
        0,
        {"matcher": spec["matcher"], "hooks": [{"type": "command", "command": hook_command(cli)}]},
    )
    after = _dump(data)
    diff = "".join(
        difflib.unified_diff(
            (before or b"").decode().splitlines(True),
            after.decode().splitlines(True),
            fromfile=str(path) if before is not None else "/dev/null",
            tofile=str(path),
        )
    )
    return Plan(path, before, after, True, diff)


def install(cli: str, scope: str, project: Path, home: Path, dry_run: bool = False) -> Plan:
    """Install (or preview) the hook. Idempotent; backs up the original; writes a manifest."""
    path = target_path(cli, scope, project, home)
    plan = plan_install(cli, path)
    if dry_run or not plan.changed:
        return plan
    sd = state_dir(scope, project, home)
    sd.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest_p = sd / f"{cli}-{scope}.json"
    backup = sd / f"{cli}-{scope}.orig"
    if plan.before is not None:
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, plan.before)
        os.close(fd)
    mode = os.stat(path).st_mode & 0o777 if path.exists() else 0o600
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".sheepdogai-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, plan.after)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    manifest = {
        "path": str(path),
        "existed": plan.before is not None,
        "backup": str(backup) if plan.before is not None else None,
        "installed_sha256": hashlib.sha256(plan.after).hexdigest(),
        "cli": cli,
        "dirs_created": not path.parent.exists(),
    }
    manifest_p.write_text(json.dumps(manifest, indent=2))
    os.chmod(manifest_p, 0o600)
    return plan


def uninstall(cli: str, scope: str, project: Path, home: Path, dry_run: bool = False) -> str:
    """Reverse :func:`install` exactly when the file is unchanged since; else remove our entry."""
    sd = state_dir(scope, project, home)
    manifest_p = sd / f"{cli}-{scope}.json"
    path = target_path(cli, scope, project, home)
    if not manifest_p.exists():
        return f"nothing to uninstall for {cli} ({scope}): no manifest"
    m = json.loads(manifest_p.read_text())
    if not path.exists():
        msg = f"{path} no longer exists; removing manifest"
        if not dry_run:
            manifest_p.unlink()
        return msg
    current = path.read_bytes()
    if hashlib.sha256(current).hexdigest() == m["installed_sha256"]:
        if m["existed"]:
            msg = f"restored original {path} byte for byte"
            if not dry_run:
                path.write_bytes(Path(m["backup"]).read_bytes())
        else:
            msg = f"removed {path} (it did not exist before install)"
            if not dry_run:
                path.unlink()
    else:
        data = json.loads(current)
        spec = SPECS[cli]
        hooks = data.get("hooks", {})
        hooks[spec["event"]] = [e for e in hooks.get(spec["event"], []) if not _is_ours(e, cli)]
        if not hooks[spec["event"]]:
            del hooks[spec["event"]]
        msg = f"{path} was modified since install: removed only the {CLI_NAME} entry"
        if not dry_run:
            path.write_bytes(_dump(data))
    if not dry_run:
        manifest_p.unlink()
        bk = sd / f"{cli}-{scope}.orig"
        if bk.exists():
            bk.unlink()
    return msg
