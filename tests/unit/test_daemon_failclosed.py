"""Fail-closed matrix (invariant 1): every case returns deny or ask, never allow."""

from __future__ import annotations

import json
import os
import signal
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from sheepdogai.cli.main import main
from sheepdogai.daemon import client
from sheepdogai.daemon.server import _Server, make_server, socket_path

FIX = Path(__file__).resolve().parent.parent / "fixtures"


def payload(cli: str, name: str) -> bytes:
    return (FIX / cli / f"{name}.json").read_bytes()


def blocked_or_ask(code: int, out: str) -> bool:
    """True when the response is a block (exit 2) or a documented ask; never an allow."""
    if code == 2:
        return True
    return (
        code == 0
        and bool(out)
        and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "ask"
    )


@pytest.fixture
def daemon(runtime: Path, project: Path) -> Iterator[_Server]:
    srv = make_server(project)
    assert not isinstance(srv, int)
    t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.gateway.close()
    srv.server_close()


def test_daemon_down_and_no_autostart(runtime: Path, project: Path) -> None:
    code, out, err = client.request(
        "claude", payload("claude", "bash_npm_test"), project=str(project), autostart=False
    )
    assert code == 2 and "fail closed" in err and out == ""


def test_socket_missing_path(runtime: Path, project: Path) -> None:
    code, _, err = client.request(
        "claude", b"{}", project=str(project), autostart=False, sock=str(runtime / "nope.sock")
    )
    assert code == 2 and err


def test_timeout_never_allows(runtime: Path, project: Path) -> None:
    path = str(runtime / "slow.sock")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    os.chmod(path, 0o600)
    srv.listen(1)
    conns: list[socket.socket] = []
    threading.Thread(target=lambda: conns.append(srv.accept()[0]), daemon=True).start()
    t0 = time.monotonic()
    code, _, err = client.request(
        "claude", b"{}", project=str(project), autostart=False, sock=path, timeout=0.4
    )
    srv.close()
    assert code == 2 and "in time" in err and time.monotonic() - t0 < 3


def test_garbage_response_from_daemon(runtime: Path, project: Path) -> None:
    path = str(runtime / "bad.sock")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    os.chmod(path, 0o600)
    srv.listen(1)

    def serve() -> None:
        c, _ = srv.accept()
        c.recv(100)
        c.sendall(b"not json\n")
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    code, _, err = client.request(
        "claude", b"{}", project=str(project), autostart=False, sock=path, timeout=1
    )
    srv.close()
    assert code == 2 and err


def test_insecure_socket_permissions_rejected(runtime: Path, project: Path) -> None:
    path = str(runtime / "open.sock")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    os.chmod(path, 0o666)
    srv.listen(1)
    code, _, err = client.request("claude", b"{}", project=str(project), autostart=False, sock=path)
    srv.close()
    assert code == 2 and "owner-only" in err


def test_invalid_json_payload(daemon: _Server, project: Path) -> None:
    for raw in (b"not json", b"", b"[]", b'{"hook_event_name":"PreToolUse"}'):
        code, out, err = client.request("claude", raw, project=str(project), autostart=False)
        assert code == 2 and "malformed payload" in err, raw


def test_unknown_adapter_and_experimental_gate(daemon: _Server, project: Path) -> None:
    code, _, _ = client.request("nope", b"{}", project=str(project), autostart=False)
    assert code == 2
    code, _, err = client.request(
        "codex", payload("codex", "bash"), project=str(project), autostart=False
    )
    assert code == 2 and "experimental" in err
    code, _, _ = client.request(
        "codex", payload("codex", "bash"), experimental=True, project=str(project), autostart=False
    )
    assert code == 2  # strict mode asks, codex cannot ask -> deny


def test_unknown_tool_is_ask_or_deny(daemon: _Server, project: Path) -> None:
    raw = json.loads(payload("claude", "bash_npm_test"))
    raw["tool_name"] = "TotallyNewTool"
    raw["tool_input"] = {"x": 1}
    code, out, _ = client.request(
        "claude", json.dumps(raw).encode(), project=str(project), autostart=False
    )
    assert blocked_or_ask(code, out)


def test_deny_roundtrip_and_bypass_mode_payload(daemon: _Server, project: Path) -> None:
    code, out, err = client.request(
        "claude", payload("claude", "bash_bypass_mode_rm"), project=str(project), autostart=False
    )
    # We emit exit 2 whatever permission_mode says. Whether Claude Code honours a hook block under
    # bypassPermissions is UNVERIFIED (the hooks doc we checked does not say); see limitations.md.
    assert code == 2 and "recursive delete" in err


def test_invalid_rules_file_at_startup_and_autostart(runtime: Path, project: Path) -> None:
    (project / "sheepdogai.yaml").write_text("version: 1\nbogus_key: 1\n")
    srv = make_server(project)
    assert srv == 3
    err = (project / ".sheepdogai" / "daemon.err").read_text()
    assert "bogus_key" in err and "sheepdogai.yaml:2" in err
    code, _, msg = client.request(
        "claude", payload("claude", "bash_npm_test"), project=str(project), timeout=4
    )
    assert code == 2 and "bogus_key" in msg  # the precise error reaches the user


def test_rules_broken_while_running_denies_everything(daemon: _Server, project: Path) -> None:
    (project / "sheepdogai.yaml").write_text("version: 1\nmode: relaxed\npacks: []\n")
    code, out, _ = client.request(
        "claude", payload("claude", "bash_npm_test"), project=str(project), autostart=False
    )
    assert code == 0 and out == ""  # valid relaxed policy: allowed
    time.sleep(0.05)
    (project / "sheepdogai.yaml").write_text("version: 1\nmode: relaxed\nbogus: 1\n")
    code, _, err = client.request(
        "claude", payload("claude", "bash_npm_test"), project=str(project), autostart=False
    )
    assert code == 2 and "invalid rules" in err
    (project / "sheepdogai.yaml").write_text("version: 1\nmode: relaxed\npacks: []\n# fixed\n")
    code, _, _ = client.request(
        "claude", payload("claude", "bash_npm_test"), project=str(project), autostart=False
    )
    assert code == 0


def test_autostart_real_subprocess_and_cleanup(runtime: Path, project: Path) -> None:
    code, out, _ = client.request(
        "claude", payload("claude", "bash_npm_test"), project=str(project), timeout=8
    )
    assert blocked_or_ask(code, out)  # strict default: ask
    sp = socket_path(project)
    assert sp.exists() and (os.stat(sp).st_mode & 0o777) == 0o600
    pid = int(Path(str(sp) + ".pid").read_text())
    os.kill(pid, signal.SIGTERM)


def test_cli_hook_bad_target_and_main() -> None:
    assert main(["hook", "bogus"]) == 2
    assert main(["hook"]) == 2
