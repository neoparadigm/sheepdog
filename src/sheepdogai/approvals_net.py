"""Network notifiers (ntfy, Telegram, webhook). Optional: the core never imports this module.

These let a person approve from a phone. They are EXPERIMENTAL and tested only against local mock
servers. The wire formats of ntfy (JSON publish with ``http`` actions; ``/<topic>/json?poll=1``) and
Telegram (``sendMessage`` with an inline keyboard, ``getUpdates`` ``callback_query``) are written from
memory of those services' public APIs and are UNVERIFIED against the live services.

Credentials are read from ``~/.config/<cli>/notify.json`` (must be owner-only), not from the
environment, and ``self_protect`` denies the agent access to that directory.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from sheepdogai.approvals import (
    ApprovalRequest,
    ApprovalResponse,
    Notifier,
    Outcome,
    TerminalNotifier,
)
from sheepdogai.constants import CLI_NAME
from sheepdogai.core.errors import SheepdogError

CODES: dict[str, Outcome] = {"d": "deny", "o": "allow_once", "r": "allow_run"}


def _check_url(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    if u.scheme not in {"http", "https"} or not u.netloc:
        raise SheepdogError(f"notifier URL must be http(s): {url!r}")
    return url


def _http(
    url: str,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> bytes:
    req = urllib.request.Request(_check_url(url), data=data, headers=headers or {})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - scheme validated above
        body: bytes = r.read(1_000_000)
        return body


def _text(request: ApprovalRequest) -> str:
    return f"{request.tool}: {request.summary}\nwhy: {request.reason} [{request.rule_id}]" + (
        "\n(once only)" if request.once_only else ""
    )


class WebhookNotifier:
    """POST the request as JSON; the endpoint answers ``{"outcome": ..., "token": ...}``."""

    channel = "webhook"

    def __init__(self, url: str, secret: str | None = None, timeout_s: float = 60.0) -> None:
        self.url, self.secret, self.timeout_s = _check_url(url), secret, timeout_s

    def notify(self, request: ApprovalRequest) -> ApprovalResponse:
        """Send and wait for the synchronous answer."""
        body = json.dumps(
            {
                "request_id": request.request_id,
                "tool": request.tool,
                "summary": request.summary,
                "reason": request.reason,
                "rule_id": request.rule_id,
                "expires_at": request.expires_at,
                "once_only": request.once_only,
                "token": request.token,
            }
        ).encode()
        headers = {"Content-Type": "application/json"}
        if self.secret:
            headers["X-Signature-SHA256"] = hmac.new(
                self.secret.encode(), body, hashlib.sha256
            ).hexdigest()
        out = json.loads(_http(self.url, body, headers, self.timeout_s))
        oc = out.get("outcome")
        if oc not in CODES.values():
            return ApprovalResponse("deny", self.channel, None)
        return ApprovalResponse(oc, self.channel, out.get("token"))


class NtfyNotifier:
    """Publish with approve/deny buttons; poll a reply topic for ``<d|o|r>:<token>``."""

    channel = "ntfy"

    def __init__(self, server: str, topic: str, reply_topic: str, poll_s: float = 1.0) -> None:
        self.server, self.topic, self.reply, self.poll_s = (
            server.rstrip("/"),
            topic,
            reply_topic,
            poll_s,
        )

    def notify(self, request: ApprovalRequest) -> ApprovalResponse:
        """Publish, then poll until the request expires."""
        since = int(time.time()) - 1
        reply_url = f"{self.server}/{self.reply}"
        buttons = [("Deny", "d"), ("Allow once", "o")] + (
            [] if request.once_only else [("Allow for run", "r")]
        )
        msg = {
            "topic": self.topic,
            "title": f"{CLI_NAME} approval",
            "message": _text(request),
            "priority": 4,
            "actions": [
                {
                    "action": "http",
                    "label": lab,
                    "url": reply_url,
                    "method": "POST",
                    "body": f"{code}:{request.token}",
                }
                for lab, code in buttons
            ],
        }
        _http(self.server + "/", json.dumps(msg).encode(), {"Content-Type": "application/json"})
        while time.time() < request.expires_at:
            raw = _http(f"{reply_url}/json?poll=1&since={since}")
            for line in raw.decode().splitlines():
                try:
                    text = str(json.loads(line).get("message", ""))
                except ValueError:
                    continue
                code, _, token = text.partition(":")
                if code in CODES and token == request.token:
                    return ApprovalResponse(CODES[code], self.channel, token)
            time.sleep(self.poll_s)
        return ApprovalResponse("deny", self.channel, None)


class TelegramNotifier:
    """Inline keyboard via ``sendMessage``; ``callback_query`` from the configured chat answers."""

    channel = "telegram"

    def __init__(
        self, bot_token: str, chat_id: str | int, api_base: str = "https://api.telegram.org"
    ) -> None:
        self.base = f"{api_base.rstrip('/')}/bot{bot_token}"
        self.chat_id = str(chat_id)

    def _call(self, method: str, payload: dict[str, Any], timeout: float = 30.0) -> dict[str, Any]:
        out = json.loads(
            _http(
                f"{self.base}/{method}",
                json.dumps(payload).encode(),
                {"Content-Type": "application/json"},
                timeout,
            )
        )
        return out if isinstance(out, dict) else {}

    def notify(self, request: ApprovalRequest) -> ApprovalResponse:
        """Send the keyboard, then long-poll updates until the request expires."""
        row = [
            {"text": "Deny", "callback_data": f"d:{request.token}"},
            {"text": "Allow once", "callback_data": f"o:{request.token}"},
        ]
        if not request.once_only:
            row.append({"text": "Allow for run", "callback_data": f"r:{request.token}"})
        self._call(
            "sendMessage",
            {
                "chat_id": self.chat_id,
                "text": _text(request),
                "reply_markup": {"inline_keyboard": [row]},
            },
        )
        offset = 0
        while time.time() < request.expires_at:
            res = self._call(
                "getUpdates",
                {"timeout": 2, "offset": offset, "allowed_updates": ["callback_query"]},
            )
            for upd in res.get("result", []):
                offset = max(offset, int(upd.get("update_id", 0)) + 1)
                cq = upd.get("callback_query") or {}
                if str(cq.get("from", {}).get("id")) != self.chat_id:
                    continue  # only the configured human may answer
                code, _, token = str(cq.get("data", "")).partition(":")
                if code in CODES and token == request.token:
                    with contextlib.suppress(OSError, ValueError, urllib.error.URLError):
                        self._call("answerCallbackQuery", {"callback_query_id": cq.get("id")})
                    return ApprovalResponse(CODES[code], self.channel, token)
        return ApprovalResponse("deny", self.channel, None)


def load_notify_config(home: Path | None = None) -> dict[str, Any]:
    """Read ~/.config/<cli>/notify.json; it must be a regular file, owned by us, mode 0600."""
    p = (home or Path.home()) / ".config" / CLI_NAME / "notify.json"
    try:
        st = os.stat(p)
    except OSError as e:
        raise SheepdogError(f"notifier config {p} not readable: {e.strerror}") from e
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise SheepdogError(f"notifier config {p} must be a regular file, owned by you, mode 0600")
    data = json.loads(p.read_text())
    if not isinstance(data, dict):
        raise SheepdogError(f"notifier config {p} must be a JSON object")
    return data


def build_notifier(channel: str, home: Path | None = None) -> Notifier | None:
    """Notifier for ``approvals.channel``; None for ``cli``. Misconfiguration raises SheepdogError."""
    if channel == "cli":
        return None
    if channel == "terminal":
        return TerminalNotifier()
    cfg = load_notify_config(home).get(channel)
    if not isinstance(cfg, dict):
        raise SheepdogError(f"notify.json has no '{channel}' section")
    if channel == "webhook":
        return WebhookNotifier(cfg["url"], cfg.get("secret"))
    if channel == "ntfy":
        return NtfyNotifier(cfg["server"], cfg["topic"], cfg["reply_topic"])
    if channel == "telegram":
        return TelegramNotifier(
            cfg["bot_token"], cfg["chat_id"], cfg.get("api_base", "https://api.telegram.org")
        )
    raise SheepdogError(f"unknown approvals channel {channel!r}")
