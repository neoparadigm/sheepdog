"""``sheepdogai conformance <adapter>``: run the bundled fixtures through an adapter."""

from __future__ import annotations

import json
from importlib import resources

from sheepdogai.adapters import get_adapter
from sheepdogai.core.errors import ParseError
from sheepdogai.core.verdict import Action, Verdict

NEGATIVE = {"not_pretooluse", "not_beforetool", "not_tools_call", "not_a_tool_call"}


def cmd_conformance(name: str) -> int:
    """Return 0 when every conformance check passes."""
    a = get_adapter(name, experimental=True)
    root = resources.files("sheepdogai.adapters._fixtures").joinpath(name)
    failures: list[str] = []
    n = 0
    for f in sorted(root.iterdir(), key=lambda p: p.name):
        if not f.name.endswith(".json"):
            continue
        stem = f.name[:-5]
        n += 1
        raw = f.read_bytes()
        try:
            a.parse(raw)
            if stem in NEGATIVE:
                failures.append(f"{stem}: should have been rejected")
        except ParseError:
            if stem not in NEGATIVE:
                failures.append(f"{stem}: fixture did not parse")
    for label, v in (
        ("deny", Verdict(action=Action.DENY, reason="x")),
        ("ask", Verdict(action=Action.ASK, reason="x")),
    ):
        r = a.respond(v)
        if not a.capabilities.can_ask and label == "ask" and r.exit_code != 2:
            failures.append("ask not downgraded for adapter that cannot ask")
        if label == "deny" and (r.exit_code != 2 or not r.stderr.strip()):
            failures.append("deny must exit 2 with a reason")
    allow = a.respond(Verdict(action=Action.ALLOW))
    if allow.exit_code != 0 or allow.stderr:
        failures.append("allow must be a silent success")
    if allow.stdout:
        json.loads(allow.stdout)
    for g in (b"", b"garbage", b"[]", b"{" * 5000):
        try:
            a.parse(g)
            failures.append(f"garbage {g[:10]!r} was accepted")
        except ParseError:
            pass
    fc = a.fail_closed("")
    if fc.exit_code != 2 or not fc.stderr.strip():
        failures.append("fail_closed must exit 2 with a reason")
    for msg in failures:
        print("FAIL", msg)
    print(f"{name}: {n} fixtures, {len(failures)} failures")
    return 1 if failures else 0
