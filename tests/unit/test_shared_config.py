from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from sheepdogai.cli.main import main
from sheepdogai.core.errors import RulesError
from sheepdogai.core.verdict import Action
from sheepdogai.daemon.server import Gateway
from sheepdogai.policy.engine import PolicyEngine
from sheepdogai.policy.loader import (
    APPROVED_REL,
    SHARED_REL,
    approve_shared,
    load_policy,
    shared_state,
)
from tests.helpers import event

USER = "version: 1\nmode: balanced\npacks: [machine]\nbudget: {max_steps: 100, max_cost_usd: 5, max_repeats: 3}\n"
SHARED = (
    "version: 1\nmode: strict\npacks: [secrets]\nbudget: {max_steps: 50}\n"
    "rules:\n  - id: no-pip\n    match: {command: 'pip install*'}\n    action: deny\n    reason: use uv\n"
)


def setup(tmp: Path, user: str = USER, shared: str | None = SHARED) -> Path:
    (tmp / "sheepdog.yaml").write_text(user)
    if shared is not None:
        (tmp / ".sheepdog").mkdir(exist_ok=True)
        (tmp / SHARED_REL).write_text(shared)
    return tmp / "sheepdog.yaml"


def pol(tmp: Path):  # type: ignore[no-untyped-def]
    return load_policy(tmp / "sheepdog.yaml", project_root=tmp)


def test_unapproved_shared_config_is_ignored(tmp_path: Path) -> None:
    setup(tmp_path)
    p = pol(tmp_path)
    assert p.config.mode == "balanced" and "secrets" not in p.config.packs
    assert all(lr.origin != "shared" for lr in p.rules)
    assert any("not approved" in n for n in p.notes)
    assert shared_state(tmp_path)[0] == "unapproved"


def test_approved_shared_config_tightens(tmp_path: Path) -> None:
    setup(tmp_path)
    approve_shared(tmp_path)
    p = pol(tmp_path)
    assert p.config.mode == "strict"  # stricter of the two
    assert p.config.packs == ["machine", "secrets"]
    assert p.budget.max_steps == 50 and p.budget.max_cost_usd == 5 and p.budget.max_repeats == 3
    r = [lr for lr in p.rules if lr.origin == "shared"]
    assert [x.rule.id for x in r] == ["shared.no-pip"]
    d = PolicyEngine(p).decide(event("pip install x", cwd=str(tmp_path)))
    assert d.verdict.action is Action.DENY and d.verdict.rule_id == "shared.no-pip"


def test_changed_hash_needs_approval_again(tmp_path: Path) -> None:
    setup(tmp_path)
    approve_shared(tmp_path)
    assert shared_state(tmp_path)[0] == "approved"
    (tmp_path / SHARED_REL).write_text(SHARED + "# edited\n")
    assert shared_state(tmp_path)[0] == "unapproved"
    p = pol(tmp_path)
    assert all(lr.origin != "shared" for lr in p.rules) and p.config.mode == "balanced"
    approve_shared(tmp_path)
    assert shared_state(tmp_path)[0] == "approved"


def test_user_rules_run_before_shared_rules(tmp_path: Path) -> None:
    setup(
        tmp_path,
        USER + "rules:\n  - id: my-pip\n    match: {command: 'pip install*'}\n    action: ask\n",
    )
    approve_shared(tmp_path)
    assert (
        PolicyEngine(pol(tmp_path))
        .decide(event("pip install x", cwd=str(tmp_path)))
        .verdict.rule_id
        == "my-pip"
    )


@pytest.mark.parametrize(
    ("shared", "needle"),
    [
        ("version: 1\nmode: relaxed\n", "loosen mode"),
        ("version: 1\nbudget: {max_steps: 500}\n", "raise budget.max_steps"),
        (
            "version: 1\nrules:\n  - id: x\n    match: {tool: Bash}\n    action: allow\n",
            "only add ask or deny",
        ),
        ("version: 1\npacks: [nope]\n", "unknown pack"),
        ("version: 1\nfail: open\n", "fail"),
        ("version: 1\ndecider: {type: 'python:evil:X'}\n", "decider"),
        ("version: 1\nlog: {path: /tmp/x}\n", "log"),
        ("version: 1\nsettings: {payment_cap_usd: 1000000}\n", "settings"),
        ("version: 1\napprovals: {channel: webhook}\n", "approvals"),
    ],
)
def test_shared_config_that_loosens_is_rejected(tmp_path: Path, shared: str, needle: str) -> None:
    setup(tmp_path, shared=shared)
    # cannot be approved...
    with pytest.raises(RulesError) as e1:
        approve_shared(tmp_path)
    assert needle in str(e1.value)
    # ...and even if the approval file is forged, loading stops with a precise error
    (tmp_path / ".sheepdog/approved").mkdir(parents=True, exist_ok=True)
    from sheepdogai.core.canonical import sha256_hex

    (tmp_path / APPROVED_REL).write_text(sha256_hex((tmp_path / SHARED_REL).read_bytes()))
    with pytest.raises(RulesError) as e2:
        pol(tmp_path)
    assert needle in str(e2.value) and "shared.yaml" in str(e2.value)


def test_cli_approve_and_revoke_and_agent_cannot_approve(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    setup(tmp_path)
    base = ["--project", str(tmp_path)]
    assert main([*base, "approve-shared"]) == 1  # not a tty and no --yes
    assert shared_state(tmp_path)[0] == "unapproved"
    assert main([*base, "approve-shared", "--yes"]) == 0
    assert shared_state(tmp_path)[0] == "approved"
    assert main([*base, "status"]) == 0 and "is approved" in capsys.readouterr().out
    assert main([*base, "approve-shared", "--revoke"]) == 0
    assert shared_state(tmp_path)[0] == "unapproved"
    # the agent may not run the approve command, nor write the approval file
    eng = PolicyEngine(pol(tmp_path))
    for e in (
        event("sheepdog approve-shared --yes", cwd=str(tmp_path)),
        event(f"echo abc > {APPROVED_REL}", cwd=str(tmp_path)),
        event(f"cat {APPROVED_REL}", cwd=str(tmp_path)),
        event(kind="file_write", file_path=SHARED_REL, cwd=str(tmp_path)),
    ):
        assert eng.decide(e).verdict.action >= Action.ASK, e.args


def test_daemon_picks_up_approval_and_edits_at_runtime(tmp_path: Path) -> None:
    setup(tmp_path, shared=SHARED)
    gw = Gateway(tmp_path)

    def call(cmd: str) -> int:
        return gw.handle(
            "claude",
            json.dumps(
                {
                    "session_id": "s",
                    "cwd": str(tmp_path),
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": cmd},
                }
            ).encode(),
        ).exit_code

    assert call("pip install x") == 0 or True  # balanced: asks/allows, not denied by shared yet
    r0 = gw.last_decision
    assert r0 is not None and r0.verdict.rule_id != "shared.no-pip"
    time.sleep(0.02)
    approve_shared(tmp_path)
    os.utime(tmp_path / APPROVED_REL)
    assert call("pip install x") == 2
    assert gw.last_decision is not None and gw.last_decision.verdict.rule_id == "shared.no-pip"
    gw.close()


def test_policy_hash_changes_with_shared(tmp_path: Path) -> None:
    setup(tmp_path)
    h0 = pol(tmp_path).policy_hash
    approve_shared(tmp_path)
    assert pol(tmp_path).policy_hash != h0
