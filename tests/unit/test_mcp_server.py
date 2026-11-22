"""sheepdogai's own MCP server: read-only, plain-language answers, no way to loosen the guard."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from sheepdogai.adapters.mcp_server import TOOLS, handle, serve


def rpc(method: str, params: dict | None = None, mid: int = 1) -> dict:  # type: ignore[type-arg]
    return {"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}}


def call(tmp_path: Path, name: str, **args: object) -> dict:  # type: ignore[type-arg]
    r = handle(rpc("tools/call", {"name": name, "arguments": args}), tmp_path, tmp_path)
    assert r is not None
    return r["result"]  # type: ignore[no-any-return]


def test_initialize_and_list(tmp_path: Path) -> None:
    r = handle(rpc("initialize"), tmp_path, tmp_path)
    assert r and r["result"]["serverInfo"]["name"] == "sheepdogai"
    lst = handle(rpc("tools/list"), tmp_path, tmp_path)
    assert lst and len(lst["result"]["tools"]) == len(TOOLS)


def test_every_tool_is_read_only_and_none_can_change_rules() -> None:
    assert all(t["annotations"]["readOnlyHint"] for t in TOOLS)
    names = " ".join(t["name"] for t in TOOLS)
    for forbidden in ("allow", "block", "mode", "install", "uninstall", "approve", "setup"):
        assert forbidden not in names


def test_notifications_get_no_reply(tmp_path: Path) -> None:
    assert (
        handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, tmp_path, tmp_path)
        is None
    )


def test_check_is_a_dry_run_in_plain_words(tmp_path: Path) -> None:
    assert call(tmp_path, "sheepdogai_check", command="sudo whoami")["content"][0][
        "text"
    ].startswith("BLOCKED")
    ok = call(tmp_path, "sheepdogai_check", command="npm test")["content"][0]["text"]
    assert not ok.startswith("BLOCKED")
    assert not (tmp_path / ".sheepdogai").exists()  # nothing was logged or written


@pytest.mark.parametrize("run", ["../x", "a/b", "..", "a\\b", ""])
def test_verify_log_refuses_paths(tmp_path: Path, run: str) -> None:
    assert call(tmp_path, "sheepdogai_verify_log", run=run)["isError"] is True


def test_bad_input_is_a_tool_error_not_a_crash(tmp_path: Path) -> None:
    assert call(tmp_path, "sheepdogai_recent", count=0)["isError"] is True
    assert call(tmp_path, "sheepdogai_check")["isError"] is True
    assert call(tmp_path, "nope")["isError"] is True


def test_recent_and_status_answer(tmp_path: Path) -> None:
    assert "Nothing recorded" in call(tmp_path, "sheepdogai_recent")["content"][0]["text"]
    assert call(tmp_path, "sheepdogai_status")["isError"] is False


def test_unknown_method_and_garbage_input(tmp_path: Path) -> None:
    r = handle(rpc("resources/list"), tmp_path, tmp_path)
    assert r and r["error"]["code"] == -32601
    out = io.StringIO()
    serve(tmp_path, tmp_path, io.StringIO("not json\n\n" + json.dumps(rpc("ping")) + "\n"), out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0]["error"]["code"] == -32700 and lines[1]["result"] == {}
