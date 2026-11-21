"""Supply-chain and runtime-safety tests: grep-style checks over src."""

from __future__ import annotations

import ast
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "sheepdogai"
FORBIDDEN = {
    "eval": r"\beval\s*\(",
    "exec": r"\bexec\s*\(",
    "pickle": r"\bpickle\b",
    "shell=True": r"(?<!\w)shell\s*=\s*True",
    "yaml.load": r"\byaml\.load\s*\(",
    "os.system": r"\bos\.system\s*\(",
    "marshal": r"\bmarshal\b",
}


@pytest.mark.parametrize("name", FORBIDDEN)
def test_no_forbidden_constructs_in_src(name: str) -> None:
    hits = [
        str(p.relative_to(ROOT))
        for p in SRC.rglob("*.py")
        if re.search(FORBIDDEN[name], p.read_text())
    ]
    assert hits == [], f"{name} found in {hits}"


@pytest.mark.parametrize("pkg", ["core", "policy", "log", "redact", "budget", "graph", "ontology"])
def test_no_network_imports_in_core_packages(pkg: str) -> None:
    bad = {
        "socket",
        "urllib",
        "http",
        "requests",
        "httpx",
        "aiohttp",
        "ssl",
        "smtplib",
        "ftplib",
        "xmlrpc",
    }
    for p in (SRC / pkg).rglob("*.py"):
        tree = ast.parse(p.read_text())
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module]
            for m in mods:
                assert m.split(".")[0] not in bad, f"{p.relative_to(ROOT)} imports {m}"


def test_telemetry_is_not_imported_by_core() -> None:
    for pkg in ("core", "policy", "log", "redact", "budget", "daemon", "adapters", "cli"):
        for p in (SRC / pkg).rglob("*.py"):
            assert "sheepdogai.telemetry" not in p.read_text(), p


def test_hygiene_tool_passes() -> None:
    r = subprocess.run(
        [sys.executable, str(ROOT / "tools/check_hygiene.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stdout


def test_thin_client_imports_nothing_heavy() -> None:
    code = (
        "import sys; sys.path.insert(0, 'src'); import sheepdogai.daemon.client, sheepdogai.cli.hook;"
        "bad = [m for m in ('pydantic', 'yaml', 'sheepdogai.core', 'sheepdogai.policy', 'rdflib') if m in sys.modules];"
        "print(','.join(bad))"
    )
    r = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT, check=True
    )
    assert r.stdout.strip() == "", f"thin client pulled in: {r.stdout}"


def test_hook_fast_path_does_not_import_heavy_modules() -> None:
    code = (
        "import sys; sys.path.insert(0, 'src'); import sheepdogai.cli.main;"
        "bad = [m for m in ('pydantic', 'yaml', 'rdflib', 'sheepdogai.policy') if m in sys.modules];"
        "print(','.join(bad))"
    )
    r = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT, check=True
    )
    assert r.stdout.strip() == "", r.stdout


def test_files_are_created_owner_only(tmp_path: Path) -> None:
    from sheepdogai.cli.main import main
    from sheepdogai.daemon.server import Gateway

    assert main(["--project", str(tmp_path), "init"]) == 0
    gw = Gateway(tmp_path)
    gw.handle(
        "claude",
        b'{"session_id":"p","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}',
    )
    gw.close()
    files = [tmp_path / "sheepdog.yaml", *(tmp_path / ".sheepdog/runs").iterdir()]
    assert files
    for f in files:
        assert stat.S_IMODE(os.stat(f).st_mode) & 0o077 == 0, f
    assert stat.S_IMODE(os.stat(tmp_path / ".sheepdog/runs").st_mode) == 0o700


def test_otel_mapping_is_pure_and_uses_pinned_names() -> None:
    import json

    from sheepdogai.telemetry.otel import spans_from_records

    recs = [
        json.loads(x) for x in (ROOT / "tests/replay/golden/run.jsonl").read_text().splitlines()
    ]
    spans = spans_from_records(recs)
    assert len(spans) == 10
    a = spans[0]["attributes"]
    assert a["gen_ai.operation.name"] == "execute_tool" and a["gen_ai.tool.name"] == "Bash"
    assert all(k.startswith(("gen_ai.", "sheepdog.")) for s in spans for k in s["attributes"])
    assert spans[0]["semconv_version"] == "1.37.0"
