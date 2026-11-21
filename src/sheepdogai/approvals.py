"""Phase 2 approvals: deny / allow once / allow for this run, single-use tokens, Notifier protocol.

Rules enforced here:
* every approval is a **single-use token bound to the event hash and an expiry**;
* the agent can never read or answer one: tokens exist only in daemon memory and in the channel
  to the human, the HMAC key lives in a 0600 file that ``self_protect`` denies the agent;
* **a timeout means deny**;
* every outcome is returned to the Gateway, which logs it as a HumanApproval (outcome, channel).

No network code lives here. Network notifiers are in ``approvals_net`` (optional extra).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from sheepdogai.core.canonical import canonical_json, sha256_hex
from sheepdogai.core.events import ToolCallEvent
from sheepdogai.redact.secrets import redact_text

Outcome = Literal["deny", "allow_once", "allow_run"]
LOGGED = {"deny": "denied", "allow_once": "allow_once", "allow_run": "allow_run"}


@dataclass(frozen=True)
class ApprovalRequest:
    """What the human is shown. ``summary`` is redacted; ``token`` is the single-use answer key."""

    request_id: str
    event_id: str
    event_hash: str
    tool: str
    summary: str
    reason: str
    rule_id: str | None
    expires_at: float
    once_only: bool
    token: str


@dataclass(frozen=True)
class ApprovalResponse:
    """A human's answer, carrying the token the channel echoed back."""

    outcome: Outcome
    channel: str
    token: str | None


class Notifier(Protocol):
    """Deliver a request to a human and return their answer (blocking, bounded by the caller)."""

    channel: str

    def notify(self, request: ApprovalRequest) -> ApprovalResponse:
        """Show ``request`` to a person and return the answer."""
        ...


def event_hash(event: ToolCallEvent) -> str:
    """Hash binding an approval to exactly one event (id, tool, args, cwd)."""
    return sha256_hex(
        canonical_json(
            {
                "id": event.event_id,
                "tool": event.tool.name,
                "args": event.args,
                "cwd": event.cwd,
                "run": event.run_id,
                "seq": event.seq,
            }
        )
    )


class ApprovalBroker:
    """Mints and redeems single-use tokens; runs a Notifier with a hard timeout."""

    def __init__(self, state_dir: Path, clock: object | None = None) -> None:
        self.dir = state_dir
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.dir, 0o700)
        self._key = self._load_key()
        self._pending: dict[str, tuple[str, float]] = {}
        self._used: set[str] = set()
        self._lock = threading.Lock()
        self._now = clock if callable(clock) else time.time
        self.remembered: set[tuple[str | None, str]] = set()
        used = self.dir / "approval.used"
        if used.exists():
            self._used = set(used.read_text().split())

    def _load_key(self) -> bytes:
        p = self.dir / "approval.key"
        if p.exists():
            return p.read_bytes()
        key = secrets.token_bytes(32)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key)
        finally:
            os.close(fd)
        return key

    def _sig(self, nonce: str, ehash: str, expires: float) -> str:
        msg = f"{nonce}|{ehash}|{expires!r}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()[:16]

    def new_request(
        self,
        event: ToolCallEvent,
        summary: str,
        reason: str,
        rule_id: str | None,
        ttl_s: float,
        once_only: bool = False,
    ) -> ApprovalRequest:
        """Create a pending request and its token (valid for ``ttl_s`` seconds, once)."""
        nonce = secrets.token_hex(8)
        eh = event_hash(event)
        expires = self._now() + ttl_s
        with self._lock:
            self._pending[nonce] = (eh, expires)
        token = f"{nonce}.{self._sig(nonce, eh, expires)}"
        return ApprovalRequest(
            nonce,
            event.event_id,
            eh,
            event.tool.name,
            redact_text(summary)[:500],
            reason,
            rule_id,
            expires,
            once_only,
            token,
        )

    def redeem(self, token: str | None, ehash: str) -> bool:
        """True exactly once per token, only for the event it was minted for, before expiry."""
        if not token or "." not in token:
            return False
        nonce, _, sig = token.partition(".")
        with self._lock:
            pending = self._pending.get(nonce)
            if pending is None or nonce in self._used:
                return False
            bound_hash, expires = pending
            if self._now() > expires:
                return False
            if not hmac.compare_digest(self._sig(nonce, bound_hash, expires), sig):
                return False
            if not hmac.compare_digest(bound_hash, ehash):
                return False
            self._used.add(nonce)
            del self._pending[nonce]
            fd = os.open(self.dir / "approval.used", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, (nonce + "\n").encode())
                os.fsync(fd)
            finally:
                os.close(fd)
        return True

    def ask(
        self, notifier: Notifier, request: ApprovalRequest, timeout_s: float
    ) -> tuple[Outcome, str, str]:
        """Run ``notifier`` with a hard timeout. Returns (effective outcome, logged outcome, channel).

        Timeout, notifier error, a bad/replayed/expired token, or any allow without a valid token
        all mean deny.
        """
        box: list[ApprovalResponse | BaseException] = []

        def run() -> None:
            try:
                box.append(notifier.notify(request))
            except BaseException as e:  # a crashing notifier is a deny
                box.append(e)

        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(timeout_s)
        channel = getattr(notifier, "channel", "unknown")
        if t.is_alive() or not box:
            self.expire(request)
            return "deny", "timeout_deny", channel
        r = box[0]
        if isinstance(r, BaseException):
            self.expire(request)
            return "deny", "denied", channel
        if r.outcome == "deny":
            self.expire(request)
            return "deny", "denied", r.channel
        if not self.redeem(r.token, request.event_hash):
            return "deny", "denied", r.channel
        out: Outcome = (
            "allow_once" if (r.outcome == "allow_run" and request.once_only) else r.outcome
        )
        return out, LOGGED[out], r.channel

    def expire(self, request: ApprovalRequest) -> None:
        """Invalidate a request so a late answer cannot be used."""
        with self._lock:
            self._pending.pop(request.request_id, None)


class TerminalNotifier:
    """Ask on a terminal. ``input_fn``/``output_fn`` are injectable; default is /dev/tty."""

    channel = "terminal"

    def __init__(self, input_fn: object | None = None, output_fn: object | None = None) -> None:
        self._in = input_fn
        self._out = output_fn

    def notify(self, request: ApprovalRequest) -> ApprovalResponse:
        """Show the request and read d/o/r."""
        text = (
            f"\nsheepdog approval: {request.tool}\n  {request.summary}\n  why: {request.reason} "
            f"[{request.rule_id}]\n  (d)eny  (o)nce  (r)un-wide{' [once only]' if request.once_only else ''}: "
        )
        if callable(self._in) and callable(self._out):
            self._out(text)
            ans = str(self._in()).strip().lower()
        else:
            with open("/dev/tty", "r+") as tty:
                tty.write(text)
                tty.flush()
                ans = tty.readline().strip().lower()
        outcome: Outcome = {"o": "allow_once", "r": "allow_run"}.get(ans[:1], "deny")  # type: ignore[assignment]
        return ApprovalResponse(outcome, self.channel, request.token if outcome != "deny" else None)
