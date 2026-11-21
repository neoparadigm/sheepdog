from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from tests.helpers import event

from sheepdogai.approvals import (
    ApprovalBroker,
    ApprovalRequest,
    ApprovalResponse,
    TerminalNotifier,
    event_hash,
)
from sheepdogai.approvals_net import (
    NtfyNotifier,
    TelegramNotifier,
    WebhookNotifier,
    build_notifier,
    load_notify_config,
)
from sheepdogai.core.errors import SheepdogError
from sheepdogai.core.verdict import Action
from sheepdogai.daemon.server import Gateway
from sheepdogai.graph.builder import check_invariants, graph_from_log
from sheepdogai.log.verify import verify_log

CFG = "version: 1\nmode: relaxed\npacks: [personal]\napprovals: {ask_timeout_s: 2, remember: run}\n"


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def broker(tmp: Path, clock: Clock | None = None) -> ApprovalBroker:
    return ApprovalBroker(tmp / ".sheepdogai", clock=clock)


def req(b: ApprovalBroker, ev: Any = None, ttl: float = 60, once: bool = False) -> ApprovalRequest:
    ev = ev or event("x", kind="mcp", name="send_email", to="a@b.c")
    return b.new_request(ev, "send email to a@b.c", "external", "personal-send-external", ttl, once)


# ---- tokens -----------------------------------------------------------------


def test_token_is_single_use(tmp_path: Path) -> None:
    b = broker(tmp_path)
    r = req(b)
    assert b.redeem(r.token, r.event_hash) is True
    assert b.redeem(r.token, r.event_hash) is False  # replay


def test_token_expires(tmp_path: Path) -> None:
    clock = Clock()
    b = broker(tmp_path, clock)
    r = req(b, ttl=30)
    clock.t += 31
    assert b.redeem(r.token, r.event_hash) is False


def test_token_works_just_before_expiry(tmp_path: Path) -> None:
    clock = Clock()
    b = broker(tmp_path, clock)
    r = req(b, ttl=30)
    clock.t += 29
    assert b.redeem(r.token, r.event_hash) is True


def test_token_bound_to_event(tmp_path: Path) -> None:
    b = broker(tmp_path)
    e1 = event("a", kind="mcp", name="send_email", to="x@y.z")
    e2 = event("b", kind="mcp", name="send_email", to="x@y.z")
    r1 = req(b, e1)
    assert b.redeem(r1.token, event_hash(e2)) is False  # used for a different event
    assert b.redeem(r1.token, r1.event_hash) is True  # the wrong-event attempt did not burn it


def test_failed_attempt_for_wrong_event_does_not_burn_token(tmp_path: Path) -> None:
    b = broker(tmp_path)
    r = req(b)
    assert b.redeem(r.token, "0" * 64) is False
    assert b.redeem(r.token, r.event_hash) is True


@pytest.mark.parametrize("bad", [None, "", "x", "abc.def", "a.b.c", "0" * 16 + "." + "0" * 16])
def test_garbage_and_forged_tokens(tmp_path: Path, bad: str | None) -> None:
    b = broker(tmp_path)
    r = req(b)
    assert b.redeem(bad, r.event_hash) is False


def test_forged_signature_with_real_nonce(tmp_path: Path) -> None:
    b = broker(tmp_path)
    r = req(b)
    nonce = r.token.split(".")[0]
    assert b.redeem(f"{nonce}.{'0' * 16}", r.event_hash) is False


def test_used_nonces_survive_restart_and_files_are_private(tmp_path: Path) -> None:
    b = broker(tmp_path)
    r = req(b)
    assert b.redeem(r.token, r.event_hash)
    b2 = broker(tmp_path)
    assert b2.redeem(r.token, r.event_hash) is False
    for f in ("approval.key", "approval.used"):
        assert os.stat(tmp_path / ".sheepdogai" / f).st_mode & 0o077 == 0


# ---- ask() --------------------------------------------------------------------


class Fake:
    channel = "fake"

    def __init__(self, fn: Any) -> None:
        self.fn = fn

    def notify(self, request: ApprovalRequest) -> ApprovalResponse:
        r = self.fn(request)
        assert isinstance(r, ApprovalResponse)
        return r


def test_timeout_means_deny_and_late_answer_is_useless(tmp_path: Path) -> None:
    b = broker(tmp_path)
    r = req(b)
    late: list[ApprovalRequest] = []

    def slow(request: ApprovalRequest) -> ApprovalResponse:
        late.append(request)
        time.sleep(0.5)
        return ApprovalResponse("allow_once", "fake", request.token)

    outcome, logged, ch = b.ask(Fake(slow), r, 0.1)
    assert (outcome, logged, ch) == ("deny", "timeout_deny", "fake")
    time.sleep(0.6)
    assert b.redeem(r.token, r.event_hash) is False  # expired by the timeout


def test_notifier_crash_is_deny(tmp_path: Path) -> None:
    b = broker(tmp_path)

    def boom(request: ApprovalRequest) -> ApprovalResponse:
        raise RuntimeError("x")

    assert b.ask(Fake(boom), req(b), 1)[0] == "deny"


def test_allow_without_valid_token_is_deny(tmp_path: Path) -> None:
    b = broker(tmp_path)
    r = req(b)
    assert (
        b.ask(Fake(lambda q: ApprovalResponse("allow_once", "fake", "forged.token")), r, 1)[0]
        == "deny"
    )
    r2 = req(b)
    assert b.ask(Fake(lambda q: ApprovalResponse("allow_once", "fake", None)), r2, 1)[0] == "deny"
    r3 = req(b)
    # a token minted for another request is not accepted for this one
    other = req(b)
    assert (
        b.ask(Fake(lambda q: ApprovalResponse("allow_once", "fake", other.token)), r3, 1)[0]
        == "deny"
    )


def test_allow_run_is_downgraded_for_once_only(tmp_path: Path) -> None:
    b = broker(tmp_path)
    r = req(b, once=True)
    assert b.ask(Fake(lambda q: ApprovalResponse("allow_run", "fake", q.token)), r, 1)[:2] == (
        "allow_once",
        "allow_once",
    )
    r2 = req(b)
    assert (
        b.ask(Fake(lambda q: ApprovalResponse("allow_run", "fake", q.token)), r2, 1)[0]
        == "allow_run"
    )


def test_terminal_notifier_answers() -> None:
    for ans, want in (
        ("o", "allow_once"),
        ("r", "allow_run"),
        ("d", "deny"),
        ("", "deny"),
        ("zzz", "deny"),
    ):
        out: list[str] = []
        tn = TerminalNotifier(input_fn=lambda a=ans: a, output_fn=out.append)
        ev = event("x", kind="mcp", name="send_email")
        b = ApprovalBroker(Path("/tmp") / f"sdb{os.getpid()}")
        r = b.new_request(ev, "s", "why", "r1", 5)
        assert tn.notify(r).outcome == want and "why" in out[0]


# ---- through the gateway --------------------------------------------------------


def gw_event(name: str, session: str = "h1", **args: Any) -> bytes:
    return json.dumps(
        {
            "session_id": session,
            "cwd": "/w",
            "hook_event_name": "PreToolUse",
            "tool_name": name,
            "tool_input": args,
        }
    ).encode()


class Human:
    """A scripted approver that also records what it was shown (to prove tokens are not logged)."""

    channel = "test-phone"

    def __init__(self, answers: list[str]) -> None:
        self.answers = answers
        self.seen: list[ApprovalRequest] = []

    def notify(self, request: ApprovalRequest) -> ApprovalResponse:
        self.seen.append(request)
        a = self.answers.pop(0)
        if a == "silent":
            time.sleep(5)
        return ApprovalResponse(a if a != "silent" else "deny", self.channel, request.token)  # type: ignore[arg-type]


def mk(tmp: Path, human: Human) -> Gateway:
    (tmp / "sheepdogai.yaml").write_text(
        CFG + "settings: {own_addresses: [me@example.org], scratch_paths: []}\n"
    )
    return Gateway(tmp, notifier=human)


def test_allow_once_deny_and_timeout_are_logged_as_human_approvals(tmp_path: Path) -> None:
    h = Human(["allow_once", "deny", "silent"])
    gw = mk(tmp_path, h)
    r1 = gw.handle("claude", gw_event("mcp__x__send_email", to="bob@example.com"))
    r2 = gw.handle("claude", gw_event("mcp__x__send_email", to="eve@example.com"))
    r3 = gw.handle("claude", gw_event("mcp__x__send_email", to="zed@example.com"))
    gw.close()
    assert (r1.exit_code, r2.exit_code, r3.exit_code) == (0, 2, 2)
    assert r1.stdout == "" and "denied by human" in r2.stderr and "timed out" in r3.stderr
    p = tmp_path / ".sheepdogai/runs/h1.jsonl"
    assert verify_log(p).ok
    recs = [json.loads(x) for x in p.read_text().splitlines()]
    ap = [r["data"] for r in recs if r["kind"] == "approval"]
    assert [(a["outcome"], a["channel"]) for a in ap] == [
        ("allow_once", "test-phone"),
        ("denied", "test-phone"),
        ("timeout_deny", "test-phone"),
    ]
    text = p.read_text()
    assert all(q.token not in text for q in h.seen)  # tokens are never logged
    g = graph_from_log(p)
    assert check_invariants(g) == []
    decisions = [r["data"] for r in recs if r["kind"] == "decision"]
    assert [d["verdict"]["action"] for d in decisions] == ["allow", "deny", "deny"]
    assert decisions[0]["rules_verdict"]["action"] == "ask" and decisions[0]["verdict"][
        "decided_by"
    ].startswith("human:")


def test_gemini_cannot_ask_but_a_phone_can(tmp_path: Path) -> None:
    h = Human(["allow_once"])
    gw = mk(tmp_path, h)
    raw = json.dumps(
        {
            "session_id": "g1",
            "cwd": "/w",
            "hook_event_name": "BeforeTool",
            "tool_name": "mcp_x_send_email",
            "tool_input": {"to": "bob@example.com"},
        }
    ).encode()
    assert gw.handle("gemini", raw).exit_code == 0
    gw.close()
    # without a notifier the same call is denied (ask downgraded because Gemini cannot ask)
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "sheepdogai.yaml").write_text(CFG)
    gw2 = Gateway(plain)
    r = gw2.handle("gemini", raw.replace(b"g1", b"g2"))
    gw2.close()
    assert r.exit_code == 2 and gw2.last_decision is not None
    assert any(n.startswith("ask_downgraded") for n in gw2.last_decision.notes)


def test_allow_run_is_remembered_but_once_only_is_not(tmp_path: Path) -> None:
    h = Human(["allow_run", "allow_run", "allow_run"])
    gw = mk(tmp_path, h)
    a = gw.handle("claude", gw_event("mcp__x__send_email", to="a@example.com"))
    b = gw.handle("claude", gw_event("mcp__x__send_email", to="b@example.com"))  # remembered
    assert (a.exit_code, b.exit_code) == (0, 0) and len(h.seen) == 1
    t1 = gw.handle("claude", gw_event("mcp__x__post_tweet", text="1"))  # once_only rule
    t2 = gw.handle("claude", gw_event("mcp__x__post_tweet", text="2"))
    assert (t1.exit_code, t2.exit_code) == (0, 0) and len(h.seen) == 3  # asked both times
    gw.close()
    recs = [
        json.loads(x)["data"]
        for x in (tmp_path / ".sheepdogai/runs/h1.jsonl").read_text().splitlines()
        if '"approval"' in x
    ]
    assert [r["channel"] for r in recs][:2] == ["test-phone", "remembered"]
    assert recs[2]["outcome"] == "allow_once"  # allow_run downgraded for a once_only rule


def test_deny_verdicts_never_reach_the_human(tmp_path: Path) -> None:
    h = Human([])
    gw = mk(tmp_path, h)
    r = gw.handle("claude", gw_event("mcp__x__purchase_item", amount=5000))  # over cap: deny
    gw.close()
    assert r.exit_code == 2 and h.seen == []


def test_agent_cannot_read_or_answer_approvals(tmp_path: Path) -> None:
    from tests.helpers import make_engine

    eng = make_engine(tmp_path, mode="relaxed", packs=[])
    for cmd in (
        "cat .sheepdogai/approval.key",
        "cat .sheepdogai/approval.used",
        "ls .sheepdogai/approved",
        "cat ~/.config/sheepdogai/notify.json",
        "echo 1 > .sheepdogai/approval.used",
        "cp ~/.config/sheepdogai/notify.json /tmp/x",
    ):
        assert eng.decide(event(cmd, cwd=str(tmp_path))).verdict.action is Action.DENY, cmd
    for p in (".sheepdogai/approval.key", "~/.config/sheepdogai/notify.json"):
        d = eng.decide(event(kind="file_read", file_path=p, cwd=str(tmp_path)))
        assert d.verdict.action is Action.DENY, p


# ---- network notifiers against local mock servers ------------------------------


class Mock(BaseHTTPRequestHandler):
    log: list[tuple[str, str, bytes]] = []
    replies: list[str] = []
    script: Any = None

    def log_message(self, *a: Any) -> None:
        pass

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""

    def _send(self, obj: Any) -> None:
        data = json.dumps(obj).encode() if not isinstance(obj, bytes) else obj
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        body = self._body()
        type(self).log.append(("POST", self.path, body))
        self._send(type(self).script(self.path, body, self.headers) if type(self).script else {})

    def do_GET(self) -> None:
        type(self).log.append(("GET", self.path, b""))
        self._send(type(self).script(self.path, b"", self.headers) if type(self).script else b"")


@pytest.fixture
def server():  # type: ignore[no-untyped-def]
    Mock.log, Mock.replies, Mock.script = [], [], None
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def make_req(
    tmp: Path, ttl: float = 5, once: bool = False
) -> tuple[ApprovalBroker, ApprovalRequest]:
    b = broker(tmp)
    return b, req(b, ttl=ttl, once=once)


def test_webhook_notifier_roundtrip_and_signature(tmp_path: Path, server: str) -> None:
    b, r = make_req(tmp_path)
    Mock.script = lambda path, body, h: {
        "outcome": "allow_once",
        "token": json.loads(body)["token"],
    }
    n = WebhookNotifier(server + "/hook", secret="s3cret", timeout_s=3)
    out = b.ask(n, r, 5)
    assert out == ("allow_once", "allow_once", "webhook")
    sent = json.loads(Mock.log[0][2])
    assert sent["summary"] and sent["request_id"] == r.request_id


def test_webhook_garbage_answer_is_deny(tmp_path: Path, server: str) -> None:
    b, r = make_req(tmp_path)
    Mock.script = lambda path, body, h: {"outcome": "allow_forever"}
    assert b.ask(WebhookNotifier(server + "/h", timeout_s=3), r, 5)[0] == "deny"


def test_notifier_urls_must_be_http(tmp_path: Path) -> None:
    for bad in ("file:///etc/passwd", "ftp://x/y", "javascript:alert(1)", "//x"):
        with pytest.raises(SheepdogError):
            WebhookNotifier(bad)


def test_ntfy_notifier_publishes_buttons_and_reads_reply(tmp_path: Path, server: str) -> None:
    b, r = make_req(tmp_path)

    def script(path: str, body: bytes, h: Any) -> Any:
        if path == "/":
            return {"id": "1"}
        return (json.dumps({"message": f"o:{r.token}"}) + "\n").encode()

    Mock.script = script
    n = NtfyNotifier(server, "alerts", "replies", poll_s=0.05)
    assert b.ask(n, r, 5) == ("allow_once", "allow_once", "ntfy")
    pub = json.loads(Mock.log[0][2])
    labels = [a["label"] for a in pub["actions"]]
    assert labels == ["Deny", "Allow once", "Allow for run"] and pub["topic"] == "alerts"
    assert all(a["body"].endswith(r.token) for a in pub["actions"])


def test_ntfy_once_only_has_no_run_button_and_ignores_other_tokens(
    tmp_path: Path, server: str
) -> None:
    b, r = make_req(tmp_path, ttl=1.2, once=True)
    Mock.script = lambda path, body, h: (
        {} if path == "/" else (json.dumps({"message": "o:wrongtoken"}) + "\n").encode()
    )
    n = NtfyNotifier(server, "alerts", "replies", poll_s=0.1)
    out = b.ask(n, r, 3)
    assert out[0] == "deny"  # wrong token ignored, request ran out
    assert [a["label"] for a in json.loads(Mock.log[0][2])["actions"]] == ["Deny", "Allow once"]


def test_telegram_notifier_only_accepts_the_configured_chat(tmp_path: Path, server: str) -> None:
    b, r = make_req(tmp_path)
    calls = {"n": 0}

    def script(path: str, body: bytes, h: Any) -> Any:
        if path.endswith("/sendMessage"):
            return {"ok": True}
        if path.endswith("/getUpdates"):
            calls["n"] += 1
            if calls["n"] == 1:  # a stranger tries first
                return {
                    "result": [
                        {
                            "update_id": 1,
                            "callback_query": {
                                "id": "c1",
                                "from": {"id": 666},
                                "data": f"o:{r.token}",
                            },
                        }
                    ]
                }
            return {
                "result": [
                    {
                        "update_id": 2,
                        "callback_query": {"id": "c2", "from": {"id": 42}, "data": f"r:{r.token}"},
                    }
                ]
            }
        return {"ok": True}

    Mock.script = script
    n = TelegramNotifier("TOKEN", 42, api_base=server)
    assert b.ask(n, r, 6) == ("allow_run", "allow_run", "telegram")
    sent = json.loads(next(x[2] for x in Mock.log if x[1].endswith("/sendMessage")))
    assert sent["chat_id"] == "42" and len(sent["reply_markup"]["inline_keyboard"][0]) == 3
    assert all(len(b_["callback_data"]) <= 64 for b_ in sent["reply_markup"]["inline_keyboard"][0])


def test_notify_config_must_be_private(tmp_path: Path) -> None:
    d = tmp_path / ".config" / "sheepdogai"
    d.mkdir(parents=True)
    f = d / "notify.json"
    f.write_text(json.dumps({"webhook": {"url": "http://127.0.0.1:1/x"}}))
    os.chmod(f, 0o644)
    with pytest.raises(SheepdogError):
        load_notify_config(tmp_path)
    os.chmod(f, 0o600)
    assert isinstance(build_notifier("webhook", tmp_path), WebhookNotifier)
    assert build_notifier("cli") is None
    with pytest.raises(SheepdogError):
        build_notifier("ntfy", tmp_path)  # no section
