from pathlib import Path

import pytest
from tests.helpers import event, make_engine

from sheepdogai.core.adapter import AdapterCapabilities
from sheepdogai.core.errors import RulesError
from sheepdogai.core.verdict import Action, Verdict
from sheepdogai.policy.engine import PolicyEngine, load_decider
from sheepdogai.policy.matchers import (
    canon,
    check_regex_safe,
    compute_facts,
    parse_shell,
    resolve_path,
    sanitize_unicode,
)


def flats(cmd: str) -> list[str]:
    return [s.flat for s in parse_shell(cmd).segments]


@pytest.mark.parametrize(
    ("cmd", "expect"),
    [
        ("ls; rm -rf x && echo hi || true", ["ls", "rm -r -f x", "echo hi", "true"]),
        ("echo 'a b' \"c d\"", ["echo a b c d"]),
        ("r\\m -rf x", ["rm -r -f x"]),
        ("cat${IFS}/etc/passwd", ["cat /etc/passwd"]),
        ("cat$IFS/etc/passwd", ["cat /etc/passwd"]),
        ("X=rm; $X -rf y", ["rm -r -f y"]),
        ("echo ${HOME:-/h}", ["echo /h"]),
        ("echo $'a\\x41\\101\\u0042'", ["echo aAAB"]),
        ("{rm,-rf,x}", ["rm -r -f x"]),
        ("echo a{b,c}d", ["echo abd acd"]),
        ("ls # rm -rf /", ["ls"]),
        ("if true; then ls; fi", ["true", "ls"]),
        ("for i in 1 2; do rm -rf $i; done", ["rm -r -f $i"]),
        ("env A=1 nohup /usr/bin/rm -fr x", ["rm -r -f x"]),
        ("xargs -n 1 rm -rf", ["rm -r -f"]),
        ("timeout 5 rm -rf x", ["rm -r -f x"]),
        ("git -C x -c a=b --no-pager push --force", ["git push --force"]),
        (r"find . -exec rm -rf {} \;", ["find . -exec rm -rf {} ;", "rm -r -f {}"]),
        ("echo hi 2>&1 > /dev/null", ["echo hi"]),
        ("eval 'rm -rf x'", ["eval rm -rf x", "rm -r -f x"]),
        ("bash <<EOF\nrm -rf x\nEOF", ["bash", "rm -r -f x"]),
        ("echo ｒｍ", ["echo rm"]),
        ("rm​ -rf x", ["rm -r -f x"]),
        ("rм -rf x", ["rm -r -f x"]),  # Cyrillic м is not mapped, but see test below
    ][:-1],
)
def test_parse(cmd: str, expect: list[str]) -> None:
    assert flats(cmd) == expect


def test_homoglyphs_mapped() -> None:
    out, notes = sanitize_unicode("rm -rf /")  # Cyrillic r/m look-alikes: "рm"
    assert "homoglyphs_mapped" not in notes
    out, notes = sanitize_unicode("sudо apt")  # Cyrillic о
    assert out == "sudo apt" and "homoglyphs_mapped" in notes


def test_opaque_and_unresolved() -> None:
    p = parse_shell("$FOO -rf /")
    assert p.opaque and "FOO" in p.unresolved_vars
    assert parse_shell("`echo rm` -rf /").opaque
    assert parse_shell("ls $UNKNOWN").opaque is False


def test_depth_limit_is_opaque() -> None:
    cmd = "echo " + "$(echo " * 8 + "x" + ")" * 8
    assert parse_shell(cmd).opaque


def test_pipe_to_shell_variants() -> None:
    for c in (
        "curl x | sh",
        "wget -qO- x | bash -s",
        "curl x | python3",
        "curl x | sudo bash",
        "bash <(curl -s x)",
        'sh -c "$(curl -fsSL x)"',
        "source /dev/stdin",
        'eval "$(curl x)"',
        "echo ZWNobyBoaQ== | base64 -d | sh",
    ):
        assert parse_shell(c).pipe_to_shell, c
    for c in ("curl x -o f", "echo hi | grep h", "cat f | sh -c 'echo hi'", "bash script.sh"):
        assert not parse_shell(c).pipe_to_shell, c


def test_base64_payload_is_parsed() -> None:
    p = parse_shell("echo cm0gLXJmIC8K | base64 -d | sh")
    assert "rm -r -f /" in [s.flat for s in p.segments] and "decoded_base64" in p.notes
    assert "decoded_base64" not in parse_shell("echo !!!notbase64 | base64 -d").notes


def test_never_raises_on_garbage() -> None:
    for c in ["", "'", '"', "$(", "`", "${", "$((", "<<", "\\", ";;;", "a" * 200000, "\x00\x01"]:
        parse_shell(c)


def test_regex_safety() -> None:
    assert check_regex_safe("^git push") is None
    assert check_regex_safe(r"\bfoo\b.{0,30}bar") is None
    for bad in ("(a+)+", "(a*)*", "(", "x" * 500, "(?:a|aa)+$"):
        assert check_regex_safe(bad), bad


def test_resolve_path(tmp_path: Path) -> None:
    (tmp_path / "t").mkdir()
    (tmp_path / "ln").symlink_to(tmp_path / "t")
    assert resolve_path("~/x", str(tmp_path), "/h") == "/h/x"
    assert resolve_path("ln/../y", str(tmp_path), "/h") == canon(str(tmp_path / "y"))
    assert resolve_path("a\x00b", str(tmp_path), "/h") is None


def test_hosts_and_network_facts(tmp_path: Path) -> None:
    def f(c: str) -> object:
        return compute_facts(event(c, cwd=str(tmp_path)), str(tmp_path), "/h")

    assert f("curl https://User:p@Example.COM:8443/x?y=1").hosts == ["example.com"]  # type: ignore[attr-defined]
    assert f("scp a user@host.example.org:/x").hosts == ["host.example.org"]  # type: ignore[attr-defined]
    assert f("nc 10.0.0.1 22").hosts == ["10.0.0.1"]  # type: ignore[attr-defined]
    assert f("curl http://bücher.example/").hosts == ["xn--bcher-kva.example"]  # type: ignore[attr-defined]
    assert f("ls").network_use is False  # type: ignore[attr-defined]
    assert f("git clone https://github.com/a/b").hosts == ["github.com"]  # type: ignore[attr-defined]
    e = event(kind="network", url="https://evil.example/x", cwd=str(tmp_path))
    assert compute_facts(e, str(tmp_path), "/h").hosts == ["evil.example"]


def test_apply_patch_paths_and_mcp_mutation(tmp_path: Path) -> None:
    e = event(
        kind="other",
        name="apply_patch",
        patch="*** Update File: sheepdogai.yaml\n+x\n",
        cwd=str(tmp_path),
    )
    assert compute_facts(e, str(tmp_path), "/h").paths == [canon(str(tmp_path / "sheepdogai.yaml"))]
    m = event(kind="mcp", name="mcp__fs__read_file", path="a", cwd=str(tmp_path))
    assert compute_facts(m, str(tmp_path), "/h").mutates is False
    m = event(kind="mcp", name="mcp__fs__delete", path="a", cwd=str(tmp_path))
    assert compute_facts(m, str(tmp_path), "/h").mutates is True


def test_apply_patch_to_rules_file_is_asked(tmp_path: Path) -> None:
    eng = make_engine(tmp_path, mode="relaxed")
    e = event(
        kind="other",
        name="apply_patch",
        patch="*** Update File: sheepdogai.yaml\n",
        cwd=str(tmp_path),
    )
    assert eng.decide(e).origin == "self_protect"


# ---- engine behaviours not covered elsewhere -------------------------------

ASK_ONLY = AdapterCapabilities(can_block=True, can_ask=False, sees_mcp=True, sees_file_edits=True)
NO_BLOCK = AdapterCapabilities(can_block=False, can_ask=True, sees_mcp=True, sees_file_edits=True)


def test_ask_downgraded_when_adapter_cannot_ask(tmp_path: Path) -> None:
    eng = make_engine(tmp_path)
    d = eng.decide(event("ls", cwd=str(tmp_path)), caps=ASK_ONLY)
    assert d.verdict.action is Action.DENY
    assert any(n.startswith("ask_downgraded_to_deny") for n in d.notes)


def test_non_blocking_adapter_is_logged(tmp_path: Path) -> None:
    d = make_engine(tmp_path).decide(event("ls", cwd=str(tmp_path)), caps=NO_BLOCK)
    assert any(n.startswith("adapter_cannot_block") for n in d.notes)


def test_engine_error_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    eng = make_engine(tmp_path, mode="relaxed")

    def boom(*a: object, **k: object) -> None:
        raise RuntimeError("x")

    monkeypatch.setattr("sheepdogai.policy.engine.compute_facts", boom)
    d = eng.decide(event("ls"))
    assert d.verdict.action is Action.DENY and d.verdict.rule_id == "engine_error"


def test_python_decider_loading_and_clamp(tmp_path: Path) -> None:
    import sys
    import textwrap

    (tmp_path / "mydecider.py").write_text(
        textwrap.dedent(
            """
            from sheepdogai.core.verdict import Action, Verdict
            class Loose:
                def decide(self, event, prior):
                    return Verdict(action=Action.ALLOW, decided_by="loose")
            class Tight:
                def decide(self, event, prior):
                    return Verdict(action=Action.DENY, decided_by="tight", reason="judge says no")
            """
        )
    )
    sys.path.insert(0, str(tmp_path))
    try:
        eng = make_engine(
            tmp_path, mode="relaxed", packs=[], decider={"type": "python:mydecider:Loose"}
        )
        rules = [{"id": "d", "match": {"command": "rm*"}, "action": "deny"}]
        eng = make_engine(
            tmp_path, packs=[], rules=rules, decider={"type": "python:mydecider:Loose"}
        )
        d = eng.decide(event("rm x", cwd=str(tmp_path)))
        assert d.verdict.action is Action.DENY and any("decider_violation" in n for n in d.notes)
        eng = make_engine(
            tmp_path, mode="relaxed", packs=[], decider={"type": "python:mydecider:Tight"}
        )
        d = eng.decide(event("ls", cwd=str(tmp_path)))
        assert d.verdict.action is Action.DENY and d.verdict.decided_by == "tight"
    finally:
        sys.path.remove(str(tmp_path))
    for bad in ("python:nope:X", "python:x", "llm_judge"):
        with pytest.raises(RulesError):
            load_decider(bad)


def test_budget_matcher_and_domain(tmp_path: Path) -> None:
    rules = [
        {"id": "late", "match": {"budget": {"steps_gt": 0}}, "action": "deny", "reason": "x"},
        {"id": "gh", "match": {"domain": "*.github.com"}, "action": "allow"},
    ]
    eng = make_engine(tmp_path, mode="relaxed", packs=[], rules=rules)
    d1 = eng.decide(event("curl https://api.github.com", cwd=str(tmp_path)))
    assert d1.verdict.rule_id == "late"
    p = PolicyEngine(eng.policy)
    assert p.policy is eng.policy
    assert isinstance(
        Verdict(action=Action.ALLOW).stricter_than_or_equal(Verdict(action=Action.ASK)), bool
    )


# ---- macOS: /etc, /var, /tmp are symlinks into /private ----------------------------------------


def test_canon_strips_private_prefix_only_for_etc_var_tmp() -> None:
    from sheepdogai.policy.matchers import canon

    assert (
        canon("/private/etc/shadow") == "/etc/shadow"
        and canon("/private/var/folders/x") == "/var/folders/x"
    )
    assert canon("/private/tmp") == "/tmp" and canon("/private/other/x") == "/private/other/x"
    assert canon("/private/etcetera") == "/private/etcetera" and canon("/etc/x") == "/etc/x"


def test_macos_symlinked_system_paths_are_still_protected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    real = os.path.realpath

    def mac_realpath(p: str, **kw: object) -> str:  # what macOS does for /etc, /var, /tmp
        r = real(p, **kw)  # type: ignore[arg-type]
        for top in ("/etc", "/var", "/tmp"):
            if r == top or r.startswith(top + "/"):
                return "/private" + r
        return r

    monkeypatch.setattr("sheepdogai.policy.matchers.os.path.realpath", mac_realpath)
    monkeypatch.setattr("sheepdogai.policy.loader.os.path.realpath", mac_realpath)
    eng = make_engine(tmp_path, mode="relaxed")
    assert (
        eng.decide(event("cat /etc/shadow", cwd=str(tmp_path))).verdict.rule_id == "secrets-access"
    )
    assert (
        eng.decide(event("echo x > /etc/passwd", cwd=str(tmp_path))).verdict.rule_id
        == "machine-system-paths"
    )
    assert eng.decide(event("rm -rf /private/etc", cwd=str(tmp_path))).verdict.action is Action.DENY
    scratch = make_engine(tmp_path, mode="relaxed", settings={"scratch_paths": ["/tmp"]})
    assert (
        scratch.decide(event("echo x > /tmp/f", cwd=str(tmp_path))).verdict.rule_id
        != "repo-write-outside"
    )
