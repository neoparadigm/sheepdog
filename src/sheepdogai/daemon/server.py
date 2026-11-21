"""The gateway (decision pipeline) and the local Unix-socket daemon around it.

The daemon never executes content from payloads and never shells out with payload strings.
Wire protocol: one request per connection. Request = a JSON header line
``{"adapter": ..., "experimental": bool, "len": N}\\n`` followed by N raw payload bytes.
Response = one JSON line ``{"exit_code": int, "stdout": str, "stderr": str}\\n``.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import re
import socket
import socketserver
import stat
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from sheepdogai.adapters import get_adapter
from sheepdogai.constants import CONFIG_FILE
from sheepdogai.core.adapter import Adapter, AdapterResponse
from sheepdogai.core.errors import LogError, ParseError, SheepdogError
from sheepdogai.core.events import ToolCallEvent
from sheepdogai.core.verdict import Action, BudgetState, DecisionRecord, Verdict
from sheepdogai.log.writer import RunLogWriter
from sheepdogai.policy.engine import Decision, PolicyEngine
from sheepdogai.policy.loader import Policy, load_policy

MAX_REQUEST = 20 * 1024 * 1024
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


def safe_run_id(session_id: str) -> str:
    """Make a session id safe to use as a file name."""
    s = _SAFE.sub("_", session_id)[:80].lstrip(".") or "session"
    return s


def runtime_dir() -> Path:
    """Per-user directory for sockets (0700, owned by us, not a symlink)."""
    base = os.environ.get("SHEEPDOG_RUNTIME_DIR") or f"/tmp/sheepdog-{os.getuid()}"
    p = Path(base)
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.lstat(p)
    if stat.S_ISLNK(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise SheepdogError(f"unsafe runtime directory {p}")
    return p


def socket_path(project_root: Path) -> Path:
    """Socket path for a project (hash keeps it short)."""
    import hashlib

    h = hashlib.sha256(str(project_root).encode()).hexdigest()[:16]
    return runtime_dir() / f"{h}.sock"


@dataclass
class RunSession:
    """Per-run state kept by the gateway."""

    writer: RunLogWriter
    state: BudgetState = field(default_factory=BudgetState)
    seq: int = 0
    untrusted: bool = False


class Gateway:
    """parse -> engine -> log -> respond. Every failure becomes a fail-closed response."""

    def __init__(
        self, project_root: Path, rules_path: Path | None = None, log_dir: Path | None = None
    ) -> None:
        self.project_root = project_root.resolve()
        self.rules_path = rules_path if rules_path is not None else self._find_rules()
        self._explicit_log_dir = log_dir
        self.sessions: dict[str, RunSession] = {}
        self.lock = threading.Lock()
        self.broken: str | None = None
        self._sig: tuple[float, int] | None = None
        self.engine: PolicyEngine = self._load()  # raises RulesError at startup

    def _find_rules(self) -> Path | None:
        p = self.project_root / CONFIG_FILE
        return p if p.exists() else None

    def _signature(self) -> tuple[float, int] | None:
        if self.rules_path is None:
            return None
        try:
            st = self.rules_path.stat()
            return (st.st_mtime, st.st_size)
        except OSError:
            return (-1.0, -1)

    def _load(self) -> PolicyEngine:
        self._sig = self._signature()
        pol = load_policy(self.rules_path, project_root=self.project_root)
        return PolicyEngine(pol)

    def _maybe_reload(self) -> None:
        if self.rules_path is None and (self.project_root / CONFIG_FILE).exists():
            self.rules_path = self.project_root / CONFIG_FILE
        sig = self._signature()
        if sig == self._sig:
            return
        try:
            self.engine = self._load()
            self.broken = None
        except SheepdogError as e:  # invalid rules while running: deny everything until fixed
            self._sig = sig
            self.broken = str(e)

    @property
    def policy(self) -> Policy:
        """The active policy."""
        return self.engine.policy

    def log_dir(self) -> Path:
        """Directory for run logs."""
        if self._explicit_log_dir is not None:
            return self._explicit_log_dir
        p = Path(self.policy.config.log.path)
        return p if p.is_absolute() else self.project_root / p

    def _session(self, run_id: str) -> RunSession:
        s = self.sessions.get(run_id)
        if s is None:
            s = RunSession(RunLogWriter(self.log_dir(), run_id, self.policy.policy_hash))
            self.sessions[run_id] = s
        return s

    def handle(self, adapter_name: str, raw: bytes, experimental: bool = False) -> AdapterResponse:
        """Decide one tool call. Never raises; never returns allow on failure."""
        adapter: Adapter | None = None
        try:
            adapter = get_adapter(adapter_name, experimental=experimental)
            with self.lock:
                self._maybe_reload()
                if self.broken:
                    return adapter.fail_closed(f"invalid rules: {self.broken}")
                try:
                    event = adapter.parse(raw)
                except ParseError as e:
                    self._log_rejected(str(e), raw)
                    return adapter.fail_closed(f"malformed payload: {e}")
                return self._decide(adapter, event)
        except ParseError as e:
            return AdapterResponse(stderr=f"sheepdog: {e} (fail closed)", exit_code=2)
        except Exception as e:
            reason = f"internal error {type(e).__name__}"
            if adapter is not None:
                return adapter.fail_closed(reason)
            return AdapterResponse(stderr=f"sheepdog: {reason} (fail closed)", exit_code=2)

    def _log_rejected(self, why: str, raw: bytes) -> None:
        import hashlib

        with contextlib.suppress(Exception):
            w = self._session("_rejected").writer
            w.append(
                "parse_error",
                {
                    "error": why,
                    "bytes": len(raw),
                    "sha256_prefix": hashlib.sha256(raw[:4096]).hexdigest()[:16],
                },
            )

    def _decide(self, adapter: Adapter, event: ToolCallEvent) -> AdapterResponse:
        run_id = safe_run_id(event.run_id)
        sess = self._session(run_id)
        sess.seq += 1
        event = event.model_copy(
            update={
                "run_id": run_id,
                "seq": sess.seq,
                "provenance": event.provenance.model_copy(
                    update={"untrusted_content_seen": sess.untrusted, "trusted": not sess.untrusted}
                ),
            }
        )
        t0 = time.perf_counter()
        dec = self.engine.decide(event, sess.state, adapter.capabilities)
        latency = (time.perf_counter() - t0) * 1000
        sess.state = dec.budget
        rec = DecisionRecord(
            event=event,
            verdict=dec.verdict,
            latency_ms=round(latency, 3),
            policy_hash=self.policy.policy_hash,
            notes=dec.notes,
            budget=dec.budget,
        )
        try:
            sess.writer.append(
                "decision",
                {**rec.model_dump(mode="json"), "origin": dec.origin, "adapter": adapter.name},
            )
            if dec.verdict.action is Action.ASK:
                sess.writer.append(
                    "approval",
                    {
                        "event_id": event.event_id,
                        "outcome": "delegated",
                        "channel": f"{adapter.name}_prompt",
                        "token": None,
                    },
                )
        except LogError as e:
            return adapter.fail_closed(f"cannot write log: {e}")
        if event.tool.kind in {"network", "mcp"}:
            sess.untrusted = True  # heuristic: external content may now be in the agent context
        return adapter.respond(dec.verdict)

    def close(self) -> None:
        """Close all log writers."""
        for s in self.sessions.values():
            s.writer.close()
        self.sessions.clear()


# ----------------------------------------------------------------------------- daemon


def _peer_uid_ok(sock: socket.socket) -> bool:
    if hasattr(socket, "SO_PEERCRED"):
        import struct

        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        return bool(uid == os.getuid())
    return True  # directory permissions (0700, owner-checked) protect the socket elsewhere


class _Handler(socketserver.StreamRequestHandler):
    server: _Server

    def handle(self) -> None:
        self.request.settimeout(10)
        try:
            if not _peer_uid_ok(self.request):
                return
            header = json.loads(self.rfile.readline(4096))
            n = int(header["len"])
            if not 0 <= n <= MAX_REQUEST:
                raise ValueError("bad length")
            raw = self.rfile.read(n)
            if len(raw) != n:
                raise ValueError("short read")
            resp = self.server.gateway.handle(
                str(header.get("adapter", "")), raw, bool(header.get("experimental", False))
            )
        except Exception as e:  # malformed request: fail closed
            resp = AdapterResponse(
                stderr=f"sheepdog: bad request ({type(e).__name__}) (fail closed)", exit_code=2
            )
        self.server.touch()
        out = {"exit_code": resp.exit_code, "stdout": resp.stdout, "stderr": resp.stderr}
        with contextlib.suppress(OSError):
            self.wfile.write(json.dumps(out).encode() + b"\n")


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, gateway: Gateway) -> None:
        self.gateway = gateway
        self.last = time.monotonic()
        self.lock_fd = -1
        super().__init__(path, _Handler)

    def touch(self) -> None:
        self.last = time.monotonic()


def make_server(project_root: Path, rules_path: Path | None = None) -> _Server | int:
    """Create the listening server, or return a non-zero exit code if it cannot start.

    Returns 0 (as an int) when another daemon already holds the lock for this project.
    """
    state_dir = project_root / ".sheepdog"
    state_dir.mkdir(mode=0o700, exist_ok=True)
    err_file = state_dir / "daemon.err"
    sock_path = socket_path(project_root)
    lock_fd = os.open(str(sock_path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(lock_fd)
        return 0  # another daemon is starting or running
    try:
        gw = Gateway(project_root, rules_path)
    except SheepdogError as e:
        fd = os.open(err_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, str(e).encode()[:2000])
        os.close(fd)
        print(f"sheepdog daemon: {e}", file=sys.stderr)
        os.close(lock_fd)
        return 3
    with contextlib.suppress(FileNotFoundError):
        err_file.unlink()
    with contextlib.suppress(FileNotFoundError):
        sock_path.unlink()
    old = os.umask(0o177)
    try:
        srv = _Server(str(sock_path), gw)
    finally:
        os.umask(old)
    os.chmod(sock_path, 0o600)
    srv.lock_fd = lock_fd
    pid_path = Path(str(sock_path) + ".pid")
    fd = os.open(pid_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, str(os.getpid()).encode())
    os.close(fd)
    return srv


def serve(project_root: Path, rules_path: Path | None = None, idle_s: float = 1800.0) -> int:
    """Run the daemon until idle. Returns a process exit code."""
    srv = make_server(project_root, rules_path)
    if isinstance(srv, int):
        return srv
    sock_path = Path(srv.server_address)  # type: ignore[arg-type]

    def watchdog() -> None:
        while True:
            time.sleep(1.0)
            if time.monotonic() - srv.last > idle_s:
                srv.shutdown()
                return

    threading.Thread(target=watchdog, daemon=True).start()
    try:
        srv.serve_forever(poll_interval=0.2)
    finally:
        srv.gateway.close()
        srv.server_close()
        for p in (sock_path, Path(str(sock_path) + ".pid")):
            with contextlib.suppress(FileNotFoundError):
                p.unlink()
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m sheepdogai.daemon.server``."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--rules")
    ap.add_argument("--idle", type=float, default=1800.0)
    a = ap.parse_args(argv)
    return serve(Path(a.project), Path(a.rules) if a.rules else None, a.idle)


__all__ = ["Decision", "Gateway", "Verdict", "main", "serve", "socket_path"]

if __name__ == "__main__":
    sys.exit(main())
