"""Shared conformance suite: every adapter must pass these."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sheepdogai.adapters import get_adapter
from sheepdogai.core.adapter import Adapter
from sheepdogai.core.errors import ParseError
from sheepdogai.core.verdict import Action, Verdict

FIX = Path(__file__).resolve().parent.parent / "fixtures"
CLIS = {
    "claude": "claude",
    "gemini": "gemini",
    "codex": "codex",
    "mcp": "mcp",
    "framework": "framework",
}
NEGATIVE = {"not_pretooluse", "not_beforetool", "not_tools_call", "not_a_tool_call"}


def adapter(cli: str) -> Adapter:
    return get_adapter(cli, experimental=True)


def fixtures(cli: str) -> list[Path]:
    return sorted(p for p in (FIX / cli).glob("*.json") if p.stem not in NEGATIVE)


PARAMS = [(cli, p) for cli in CLIS for p in fixtures(cli)]
IDS = [f"{c}/{p.stem}" for c, p in PARAMS]


@pytest.mark.parametrize(("cli", "path"), PARAMS, ids=IDS)
def test_parse_fixtures(cli: str, path: Path) -> None:
    ev = adapter(cli).parse(path.read_bytes())
    assert ev.schema_version == "1" and ev.tool.name and ev.session_id
    assert ev.tool.kind in {"shell", "file_read", "file_write", "network", "mcp", "other"}
    assert ev.event_id[14] == "7"


@pytest.mark.parametrize("cli", CLIS)
def test_negative_fixtures_rejected(cli: str) -> None:
    for p in (FIX / cli).glob("*.json"):
        if p.stem in NEGATIVE:
            with pytest.raises(ParseError):
                adapter(cli).parse(p.read_bytes())


@pytest.mark.parametrize("cli", CLIS)
def test_respond_deny_blocks_in_cli_format(cli: str) -> None:
    a = adapter(cli)
    r = a.respond(Verdict(action=Action.DENY, rule_id="r1", reason="nope"))
    assert r.exit_code == 2 and "nope" in r.stderr and "r1" in r.stderr and r.stderr.strip()


@pytest.mark.parametrize("cli", CLIS)
def test_respond_allow_never_blocks(cli: str) -> None:
    r = adapter(cli).respond(Verdict(action=Action.ALLOW))
    assert r.exit_code == 0 and not r.stderr
    if r.stdout:
        json.loads(r.stdout)


@pytest.mark.parametrize("cli", CLIS)
def test_ask_honours_capabilities(cli: str) -> None:
    a = adapter(cli)
    r = a.respond(Verdict(action=Action.ASK, reason="check"))
    if a.capabilities.can_ask:
        assert r.exit_code == 0 and "ask" in r.stdout
    else:  # must not let the call through when the CLI cannot ask
        assert r.exit_code == 2 and r.stderr.strip()


def test_claude_ask_uses_documented_json() -> None:
    r = adapter("claude").respond(Verdict(action=Action.ASK, rule_id="x", reason="why"))
    out = json.loads(r.stdout)["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse" and out["permissionDecision"] == "ask"
    assert "why" in out["permissionDecisionReason"]


@pytest.mark.parametrize("cli", CLIS)
def test_fail_closed_is_exit_2_with_reason(cli: str) -> None:
    r = adapter(cli).fail_closed("boom")
    assert r.exit_code == 2 and "boom" in r.stderr
    assert adapter(cli).fail_closed("").stderr.strip()  # codex: empty stderr would fail open


GARBAGE = [
    b"",
    b"   ",
    b"not json",
    b"[]",
    b'"x"',
    b"null",
    b"{}",
    b'{"hook_event_name": 1}',
    b"\xff\xfe\x00",
    b"{" * 100000,
    b'{"tool_name": "Bash"}',
    b"[" * 100000,
    b'{"session_id":"s","tool_name":"Bash","tool_input":"x","hook_event_name":"PreToolUse"}',
]


@pytest.mark.parametrize("cli", CLIS)
@pytest.mark.parametrize("raw", GARBAGE)
def test_garbage_raises_parse_error_only(cli: str, raw: bytes) -> None:
    a = adapter(cli)
    try:
        a.parse(raw)
    except ParseError:
        return
    # codex accepts string tool_input by design; anything else must have raised
    assert cli == "codex" and b'"tool_input":"x"' in raw


def big_payload(cli: str, size: int) -> dict[str, object]:
    cmd = "echo " + "A" * size
    if cli == "mcp":
        return {
            "session_id": "s",
            "cwd": "/p",
            "server": "srv",
            "request": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "t", "arguments": {"command": cmd}},
            },
        }
    if cli == "framework":
        return {
            "session_id": "s",
            "cwd": "/p",
            "tool_name": "t",
            "kind": "shell",
            "arguments": {"command": cmd},
        }
    hook = {"claude": "PreToolUse", "gemini": "BeforeTool", "codex": "PreToolUse"}[cli]
    tool = {"claude": "Bash", "gemini": "run_shell_command", "codex": "Bash"}[cli]
    return {
        "session_id": "s",
        "cwd": "/p",
        "hook_event_name": hook,
        "tool_name": tool,
        "tool_input": {"command": cmd},
    }


@pytest.mark.parametrize("cli", CLIS)
def test_ten_megabyte_payload_does_not_crash(cli: str) -> None:
    ev = adapter(cli).parse(json.dumps(big_payload(cli, 10 * 1024 * 1024)).encode())
    assert len(ev.args["command"]) > 10_000_000
    too_big = b" " * (17 * 1024 * 1024)
    with pytest.raises(ParseError):
        adapter(cli).parse(too_big)


def test_capabilities_declared() -> None:
    for cli in CLIS:
        c = adapter(cli).capabilities
        assert c.can_block is True
    assert not adapter("mcp").capabilities.can_ask and not adapter("framework").capabilities.can_ask
    assert not adapter("codex").capabilities.can_ask  # verified from Codex source
    assert not adapter("gemini").capabilities.can_ask
    assert adapter("claude").capabilities.can_ask


@pytest.mark.parametrize("name", ["codex", "mcp", "framework"])
def test_experimental_adapters_are_gated(name: str) -> None:
    with pytest.raises(ParseError):
        get_adapter(name)
    assert get_adapter(name, experimental=True).name


def test_codex_is_gated() -> None:
    with pytest.raises(ParseError):
        get_adapter("nope")


def test_kind_mapping() -> None:
    c = adapter("claude")
    kinds = {p.stem: c.parse(p.read_bytes()).tool.kind for p in fixtures("claude")}
    assert kinds["bash_npm_test"] == "shell" and kinds["write_file"] == "file_write"
    assert kinds["read_file"] == "file_read" and kinds["webfetch"] == "network"
    assert kinds["mcp_tool"] == "mcp"
    g = adapter("gemini")
    assert g.parse((FIX / "gemini/web_fetch.json").read_bytes()).args["url"].startswith("summarise")


def test_fixtures_mirrored_into_package() -> None:
    import subprocess
    import sys

    root = FIX.parent.parent
    r = subprocess.run(
        [sys.executable, str(root / "tools/sync_fixtures.py"), "--check"], check=False
    )
    assert r.returncode == 0
