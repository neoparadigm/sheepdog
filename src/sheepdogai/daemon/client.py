"""Thin hook client. Standard library only: it must start fast on every tool call.

Every failure path returns exit code 2 with a reason on stderr, which all three supported CLIs
treat as a block (see the adapter docstrings). Nothing here ever returns allow on failure.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import time
from typing import Any

FAIL = 2


def fail_closed(reason: str) -> tuple[int, str, str]:
    """The universal fail-closed response: exit 2, non-empty stderr."""
    return FAIL, "", f"sheepdogai: {reason} (fail closed)"


def find_project(start: str | None = None) -> str:
    """Nearest ancestor holding sheepdogai.yaml or .sheepdogai, else CLAUDE_PROJECT_DIR/cwd."""
    env = os.environ.get("SHEEPDOGAI_PROJECT") or os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        return os.path.realpath(env)
    cur = os.path.realpath(start or os.getcwd())
    probe = cur
    while True:
        if os.path.exists(os.path.join(probe, "sheepdogai.yaml")) or os.path.isdir(
            os.path.join(probe, ".sheepdogai")
        ):
            return probe
        parent = os.path.dirname(probe)
        if parent == probe:
            return cur
        probe = parent


def sock_for(project: str) -> str:
    """Socket path (mirrors daemon.server.socket_path without importing it)."""
    base = os.environ.get("SHEEPDOGAI_RUNTIME_DIR") or f"/tmp/sheepdogai-{os.getuid()}"
    return os.path.join(base, hashlib.sha256(project.encode()).hexdigest()[:16] + ".sock")


def _check_socket(path: str) -> str | None:
    """Return a reason string if the socket or its directory is not safely owner-only."""
    try:
        d = os.lstat(os.path.dirname(path))
        s = os.lstat(path)
    except OSError as e:
        return f"socket not available: {e.strerror}"
    if stat.S_ISLNK(d.st_mode) or d.st_uid != os.getuid() or stat.S_IMODE(d.st_mode) & 0o077:
        return "runtime directory is not owner-only"
    if not stat.S_ISSOCK(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) & 0o077:
        return "socket is not owner-only"
    return None


def _roundtrip(
    path: str, header: dict[str, object], payload: bytes, timeout: float
) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(json.dumps(header).encode() + b"\n" + payload)
        # no shutdown(): the server reads an exact length, and on macOS shutdown() raises ENOTCONN
        # when the daemon has already answered and closed, which would turn a fast reply into a block
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    out = json.loads(buf)
    if not isinstance(out, dict) or not isinstance(out.get("exit_code"), int):
        raise ValueError("malformed daemon response")
    return out


def _start_daemon(project: str) -> None:
    subprocess.Popen(
        [sys.executable, "-m", "sheepdogai.daemon.server", "--project", project],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )


def _daemon_error(project: str) -> str:
    try:
        with open(os.path.join(project, ".sheepdogai", "daemon.err"), encoding="utf-8") as f:
            return f.read(300)
    except OSError:
        return ""


def request(
    adapter: str,
    payload: bytes,
    *,
    experimental: bool = False,
    project: str | None = None,
    timeout: float | None = None,
    autostart: bool | None = None,
    sock: str | None = None,
) -> tuple[int, str, str]:
    """Ask the daemon for a verdict. Returns (exit_code, stdout, stderr); never raises."""
    try:
        timeout = (
            timeout if timeout is not None else float(os.environ.get("SHEEPDOGAI_TIMEOUT_S", "5"))
        )
        if autostart is None:
            autostart = os.environ.get("SHEEPDOGAI_NO_AUTOSTART") != "1"
        project = project or find_project()
        path = sock or sock_for(project)
        deadline = time.monotonic() + timeout
        header = {"adapter": adapter, "experimental": experimental, "len": len(payload)}
        started = False
        last_err = ""
        while True:
            problem = _check_socket(path)
            if problem is None:
                try:
                    out = _roundtrip(path, header, payload, max(0.05, deadline - time.monotonic()))
                    return (
                        int(out["exit_code"]),
                        str(out.get("stdout", "")),
                        str(out.get("stderr", "")),
                    )
                except (OSError, ValueError) as e:
                    last_err = f"{type(e).__name__}"
                    if isinstance(e, TimeoutError | socket.timeout):
                        return fail_closed("daemon did not answer in time")
            else:
                last_err = problem
                if "not owner-only" in problem:
                    return fail_closed(problem)
            if autostart and not started:
                started = True
                try:
                    _start_daemon(project)
                except OSError as e:
                    return fail_closed(f"cannot start daemon: {e.strerror}")
            if time.monotonic() >= deadline or not autostart:
                err = _daemon_error(project)
                return fail_closed(f"daemon unavailable ({last_err})" + (f": {err}" if err else ""))
            time.sleep(0.05)
    except BaseException as e:  # includes KeyboardInterrupt: never fall through to allow
        return fail_closed(f"client error {type(e).__name__}")
