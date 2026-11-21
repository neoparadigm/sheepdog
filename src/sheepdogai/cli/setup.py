"""``sheepdog setup``: detect agent CLIs, show the changes, confirm, install globally, self-test."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from sheepdogai.constants import CLI_NAME, CONFIG_FILE

DETECT = [("claude", "claude", ".claude"), ("gemini", "gemini", ".gemini")]
USER_CONFIG_TEMPLATE = """\
# {cli} user-wide policy: used in any project that has no {config} of its own.
version: 1
mode: {mode}          # strict: ask unless a rule matches | balanced: allow read-only | relaxed: allow
fail: closed
packs: [self_protect, machine, secrets, repo, network, injection]
"""


def user_config_path(home: Path) -> Path:
    """Where the user-wide policy lives."""
    return home / ".config" / CLI_NAME / CONFIG_FILE


def detect(home: Path) -> list[str]:
    """Supported agent CLIs found on this machine (binary on PATH or config directory)."""
    return [cli for cli, binary, d in DETECT if shutil.which(binary) or (home / d).is_dir()]


def self_test(home: Path) -> tuple[bool, str]:
    """Send a dangerous call through the real hook entry point; it must be blocked."""
    proj = Path(tempfile.mkdtemp(prefix="sheepdog-selftest-"))
    rt = Path(tempfile.mkdtemp(prefix="sd", dir="/tmp"))
    os.chmod(rt, 0o700)
    env = {
        **os.environ,
        "SHEEPDOG_PROJECT": str(proj),
        "SHEEPDOG_RUNTIME_DIR": str(rt),
        "HOME": str(home),
    }
    payload = json.dumps(
        {
            "session_id": "selftest",
            "cwd": str(proj),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        }
    ).encode()
    try:
        r = subprocess.run(
            [sys.executable, "-m", "sheepdogai.cli.main", "hook", "claude"],
            input=payload,
            capture_output=True,
            env=env,
            timeout=30,
            check=False,
        )
        ok = r.returncode == 2
        return ok, r.stderr.decode().strip() or f"exit {r.returncode}"
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, type(e).__name__
    finally:
        for pid in rt.glob("*.pid"):
            with contextlib.suppress(OSError, ValueError):
                os.kill(int(pid.read_text()), signal.SIGTERM)
        shutil.rmtree(proj, ignore_errors=True)
        shutil.rmtree(rt, ignore_errors=True)


def cmd_setup(home: Path, yes: bool, mode: str, undo: bool) -> int:
    """Install (or undo) the hook for every detected agent, user-wide."""
    from sheepdogai.cli import install as inst

    targets = detect(home)
    if not targets:
        print(
            "No supported agent CLI found (looked for Claude Code and Gemini CLI).\n"
            f"Install one, or run `{CLI_NAME} install <claude|gemini|codex>` in a project."
        )
        return 1
    print(f"Found: {', '.join(targets)}")
    if undo:
        for cli in targets:
            print(inst.uninstall(cli, "user", home, home))
        print(
            f"Hooks removed. Your user policy ({user_config_path(home)}) and logs were left in place."
        )
        return 0
    if shutil.which(CLI_NAME) is None:
        print(
            f"warning: `{CLI_NAME}` is not on your PATH, but the hook runs it. Install the tool first "
            "(uv tool install sheepdogai) or the agent's hook calls will fail closed (block everything)."
        )
    plans = [inst.install(cli, "user", home, home, dry_run=True) for cli in targets]
    cfg = user_config_path(home)
    print("\nThis will change:")
    for p in plans:
        print(f"\n  {p.path}" + ("  (already installed, no change)" if not p.changed else ""))
        for line in p.diff.splitlines():
            print("    " + line)
    if not cfg.exists():
        print(f"\n  {cfg}  (new, mode={mode})")
    if all(not p.changed for p in plans) and cfg.exists():
        print("\nNothing to do: already set up.")
        return 0
    if not yes:
        if not sys.stdin.isatty():
            print("\nNot a terminal: pass --yes to apply without asking.", file=sys.stderr)
            return 1
        try:
            input("\nPress Enter to apply, Ctrl-C to cancel. ")
        except (KeyboardInterrupt, EOFError):
            print("\ncancelled; nothing changed")
            return 1
    for cli in targets:
        inst.install(cli, "user", home, home)
    if not cfg.exists():
        cfg.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(cfg, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(
            fd, USER_CONFIG_TEMPLATE.format(cli=CLI_NAME, config=CONFIG_FILE, mode=mode).encode()
        )
        os.close(fd)
    ok, msg = self_test(home)
    print(f"\nself-test: {'blocked `rm -rf /` as expected' if ok else 'FAILED'}  ({msg})")
    print(f"\nDone. Restart your agent. Undo anytime: {CLI_NAME} setup --undo")
    return 0 if ok else 1
