"""MCP proxy (fail-closed, passthrough, redaction) and the Python wrapper."""

from __future__ import annotations

import io
import json
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from sheepdogai.adapters.mcp_proxy import McpProxy, default_decide, error_result, redact_result
from sheepdogai.adapters.wrap import ToolBlocked, wrap
from sheepdogai.daemon.server import Gateway

FAKE_SERVER = textwrap.dedent(
    """
    import json, sys
    for line in sys.stdin:
        m = json.loads(line)
        if "id" not in m:
            continue
        meth = m.get("method")
        if meth == "initialize":
            res = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake"}}
        elif meth == "tools/list":
            res = {"tools": [{"name": "echo"}, {"name": "leak"}, {"name": "delete_file"}]}
        elif meth == "tools/call":
            n = m["params"]["name"]
            txt = "AKIAIOSFODNN7EXAMPLE and password=hunter2hunter2" if n == "leak" else "ran " + n
            res = {"content": [{"type": "text", "text": txt}], "isError": False}
        else:
            res = {}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": res}) + "\\n")
        sys.stdout.flush()
    """
)


def rpc(id_: int, method: str, **params: Any) -> bytes:
    return (
        json.dumps({"jsonrpc": "2.0", "id": id_, "method": method, "params": params}).encode()
        + b"\n"
    )


def run_proxy(tmp: Path, lines: list[bytes], decide: Any) -> list[dict[str, Any]]:
    srv = tmp / "fake_server.py"
    srv.write_text(FAKE_SERVER)
    out = io.BytesIO()
    p = McpProxy(
        [sys.executable, str(srv)],
        "fake",
        "sess",
        str(tmp),
        decide,
        io.BytesIO(b"".join(lines)),
        out,
    )
    assert p.run() == 0
    return [json.loads(x) for x in out.getvalue().splitlines()]


def gateway_decide(tmp: Path, cfg: str = "version: 1\nmode: relaxed\n") -> Any:
    (tmp / "sheepdog.yaml").write_text(cfg)
    gw = Gateway(tmp)

    def decide(payload: bytes) -> tuple[int, str, str]:
        r = gw.handle("mcp", payload, experimental=True)
        return r.exit_code, r.stdout, r.stderr

    decide.gw = gw  # type: ignore[attr-defined]
    return decide


def test_passthrough_and_allowed_call(tmp_path: Path) -> None:
    d = gateway_decide(tmp_path)
    msgs = run_proxy(
        tmp_path,
        [
            rpc(1, "initialize"),
            rpc(2, "tools/list"),
            rpc(3, "tools/call", name="echo", arguments={}),
        ],
        d,
    )
    d.gw.close()
    by_id = {m["id"]: m for m in msgs}
    assert by_id[1]["result"]["serverInfo"]["name"] == "fake"
    assert [t["name"] for t in by_id[2]["result"]["tools"]] == [
        "echo",
        "leak",
        "delete_file",
    ]  # untouched
    assert (
        by_id[3]["result"]["content"][0]["text"] == "ran echo"
        and by_id[3]["result"]["isError"] is False
    )


def test_denied_call_returns_error_result_naming_the_rule(tmp_path: Path) -> None:
    d = gateway_decide(
        tmp_path,
        "version: 1\nmode: relaxed\nrules:\n  - id: no-delete\n    match: {tool: 'mcp__fake__delete_*'}\n    action: deny\n    reason: no deleting\n",
    )
    msgs = run_proxy(
        tmp_path,
        [
            rpc(1, "tools/call", name="delete_file", arguments={"path": "x"}),
            rpc(2, "tools/call", name="echo", arguments={}),
        ],
        d,
    )
    d.gw.close()
    by_id = {m["id"]: m for m in msgs}
    r = by_id[1]["result"]
    assert (
        r["isError"] is True
        and "no-delete" in r["content"][0]["text"]
        and "no deleting" in r["content"][0]["text"]
    )
    assert by_id[2]["result"]["content"][0]["text"] == "ran echo"  # the server never saw call 1


def test_denied_call_is_never_forwarded(tmp_path: Path) -> None:
    seen: list[str] = []

    def decide(payload: bytes) -> tuple[int, str, str]:
        seen.append(json.loads(payload)["request"]["params"]["name"])
        return 2, "", "sheepdog: blocked [r1]: nope"

    msgs = run_proxy(
        tmp_path, [rpc(7, "tools/call", name="echo", arguments={}), rpc(8, "tools/list")], decide
    )
    assert seen == ["echo"]
    assert {m["id"] for m in msgs} == {7, 8}
    assert next(m for m in msgs if m["id"] == 7)["result"]["isError"] is True
    assert "tools" in next(m for m in msgs if m["id"] == 8)["result"]


def test_fail_closed_when_decider_raises_or_daemon_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(payload: bytes) -> tuple[int, str, str]:
        raise RuntimeError("down")

    msgs = run_proxy(tmp_path, [rpc(1, "tools/call", name="echo", arguments={})], boom)
    assert (
        msgs[0]["result"]["isError"] is True
        and "fail closed" in msgs[0]["result"]["content"][0]["text"]
    )
    # the real default decider with the daemon stopped and no autostart
    rt = tmp_path / "rt"
    rt.mkdir(mode=0o700)
    monkeypatch.setenv("SHEEPDOG_RUNTIME_DIR", str(rt))
    monkeypatch.setenv("SHEEPDOG_NO_AUTOSTART", "1")
    monkeypatch.setenv("SHEEPDOG_PROJECT", str(tmp_path))
    msgs = run_proxy(tmp_path, [rpc(1, "tools/call", name="echo", arguments={})], default_decide)
    assert (
        msgs[0]["result"]["isError"] is True
        and "fail closed" in msgs[0]["result"]["content"][0]["text"]
    )
    assert not any(m["result"].get("content", [{}])[0].get("text") == "ran echo" for m in msgs)


def test_secret_redaction_in_results_only(tmp_path: Path) -> None:
    d = gateway_decide(tmp_path)
    msgs = run_proxy(
        tmp_path, [rpc(1, "tools/call", name="leak", arguments={}), rpc(2, "tools/list")], d
    )
    d.gw.close()
    text = next(m for m in msgs if m["id"] == 1)["result"]["content"][0]["text"]
    assert (
        "AKIAIOSFODNN7EXAMPLE" not in text and "hunter2hunter2" not in text and "REDACTED" in text
    )
    assert (
        next(m for m in msgs if m["id"] == 2)["result"]["tools"][1]["name"] == "leak"
    )  # not rewritten


def test_unchanged_results_are_byte_identical() -> None:
    line = b'{"jsonrpc":"2.0",  "id":1,"result":{"content":[{"type":"text","text":"hello"}]}}\n'
    assert redact_result(line) == line
    assert redact_result(b"not json\n") == b"not json\n"


def test_batched_tools_call_is_refused(tmp_path: Path) -> None:
    batch = (
        json.dumps(
            [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "echo"}}]
        ).encode()
        + b"\n"
    )
    msgs = run_proxy(tmp_path, [batch], lambda p: (0, "", ""))
    assert msgs[0]["error"]["code"] == -32600 and "fail closed" in msgs[0]["error"]["message"]


def test_error_result_shape() -> None:
    m = json.loads(error_result(5, "x"))
    assert m == {
        "jsonrpc": "2.0",
        "id": 5,
        "result": {"content": [{"type": "text", "text": "x"}], "isError": True},
    }


def test_event_from_proxy_uses_mcp_naming_and_graph(tmp_path: Path) -> None:
    d = gateway_decide(tmp_path)
    run_proxy(tmp_path, [rpc(1, "tools/call", name="echo", arguments={"path": "a"})], d)
    d.gw.close()
    log = next((tmp_path / ".sheepdog/runs").glob("sess.jsonl")).read_text()
    assert "mcp__fake__echo" in log and "mcp_proxy:fake" in log


# ---- wrap() ---------------------------------------------------------------------


def test_wrap_allows_blocks_and_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "sheepdog.yaml").write_text(
        "version: 1\nmode: relaxed\nrules:\n  - id: no-rm\n    match: {command: 'rm *'}\n    action: deny\n    reason: no rm\n"
    )
    gw = Gateway(tmp_path)
    calls: list[str] = []

    def run_shell(command: str, timeout: int = 5) -> str:
        calls.append(command)
        return "ok"

    g = wrap(run_shell, kind="shell", gateway=gw, framework="test")
    assert g("ls") == "ok" and calls == ["ls"]
    with pytest.raises(ToolBlocked, match="no-rm"):
        g("rm -rf x")
    assert calls == ["ls"]  # never called
    assert g.__name__ == "run_shell"

    class Dead:
        def handle(self, *a: Any, **k: Any) -> Any:
            raise RuntimeError("daemon down")

    h = wrap(run_shell, kind="shell", gateway=Dead())
    with pytest.raises(ToolBlocked, match="could not obtain a decision"):
        h("ls")
    assert calls == ["ls"]
    gw.close()


def test_wrap_without_daemon_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rt = tmp_path / "rt"
    rt.mkdir(mode=0o700)
    monkeypatch.setenv("SHEEPDOG_RUNTIME_DIR", str(rt))
    monkeypatch.setenv("SHEEPDOG_NO_AUTOSTART", "1")
    monkeypatch.setenv("SHEEPDOG_PROJECT", str(tmp_path))
    ran: list[int] = []
    t = wrap(lambda: ran.append(1), name="t")
    with pytest.raises(ToolBlocked):
        t()
    assert ran == []


def test_top_level_wrap_is_lazy_and_works(tmp_path: Path) -> None:
    import sheepdogai

    (tmp_path / "sheepdog.yaml").write_text("version: 1\nmode: relaxed\npacks: []\n")
    gw = Gateway(tmp_path)
    f = sheepdogai.wrap(lambda x: x * 2, name="double", gateway=gw)
    assert f(21) == 42
    gw.close()
