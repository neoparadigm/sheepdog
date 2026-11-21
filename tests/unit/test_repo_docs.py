"""Documentation quality gates: docstrings, examples, links, required files."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from sheepdogai.policy.loader import load_policy

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "sheepdogai"


def _public_defs(tree: ast.Module) -> list[ast.AST]:
    """Module-level functions/classes and class methods (nested helpers are not public API)."""
    out: list[ast.AST] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            out.append(node)
            if isinstance(node, ast.ClassDef):
                out.extend(
                    n for n in node.body if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
                )
    return out


def test_every_public_function_class_and_module_has_a_docstring() -> None:
    missing: list[str] = []
    for p in sorted(SRC.rglob("*.py")):
        tree = ast.parse(p.read_text())
        rel = p.relative_to(ROOT)
        if p.stat().st_size > 0 and ast.get_docstring(tree) is None:
            missing.append(f"{rel}: module")
        for node in _public_defs(tree):
            name = node.name  # type: ignore[attr-defined]
            if name.startswith("_"):
                continue
            if ast.get_docstring(node) is None:  # type: ignore[arg-type]
                missing.append(f"{rel}:{node.lineno} {name}")  # type: ignore[attr-defined]
    assert missing == [], "\n".join(missing)


@pytest.mark.parametrize("f", sorted((ROOT / "examples").glob("*.yaml")), ids=lambda p: p.name)
def test_examples_are_valid_policies(f: Path) -> None:
    pol = load_policy(f, project_root=Path("/work/proj"))
    assert pol.config.fail == "closed" and pol.rules[0].origin == "self_protect"


def test_required_repo_files_exist_and_have_content() -> None:
    for name in [
        "README.md",
        "LICENSE",
        "NOTICE",
        "SECURITY.md",
        "GOVERNANCE.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "CHANGELOG.md",
        "CITATION.cff",
        "docs/threat-model.md",
        "docs/limitations.md",
        "docs/architecture.md",
        "docs/adr/0001-fail-closed.md",
        "docs/adr/0002-decider-only-stricter.md",
        ".github/workflows/ci.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/release.yml",
        ".github/workflows/scorecard.yml",
        ".github/CODEOWNERS",
        ".github/dependabot.yml",
        ".github/PULL_REQUEST_TEMPLATE.md",
        "uv.lock",
    ]:
        assert (ROOT / name).stat().st_size > 20, name
    assert (ROOT / "src/sheepdogai/py.typed").exists()
    assert "Apache License" in (ROOT / "LICENSE").read_text()


def test_markdown_relative_links_resolve() -> None:
    bad: list[str] = []
    for md in [*ROOT.glob("*.md"), *(ROOT / "docs").rglob("*.md")]:
        for m in re.finditer(r"\]\(([^)#\s]+)(#[^)]*)?\)", md.read_text()):
            target = m.group(1)
            if re.match(r"^[a-z]+:", target):
                continue
            if not (md.parent / target).exists():
                bad.append(f"{md.relative_to(ROOT)} -> {target}")
    assert bad == []


def test_workflows_pin_actions_by_sha_and_default_to_read_all() -> None:
    for wf in (ROOT / ".github/workflows").glob("*.yml"):
        text = wf.read_text()
        assert re.search(r"^permissions: read-all$", text, re.M), wf.name
        for m in re.finditer(r"uses:\s*([^\s#]+)", text):
            ref = m.group(1)
            assert re.search(r"@[0-9a-f]{40}$", ref), (
                f"{wf.name}: {ref} is not pinned by commit SHA"
            )


def test_name_lives_in_one_constant() -> None:
    from sheepdogai.constants import CLI_NAME, PACKAGE_NAME

    assert (PACKAGE_NAME, CLI_NAME) == ("sheepdogai", "sheepdogai")
    hits = [
        p for p in SRC.rglob("*.py") if p.name != "constants.py" and '"sheepdogai"' in p.read_text()
    ]
    assert hits == []


def test_readme_does_not_use_the_forbidden_word() -> None:
    text = (ROOT / "README.md").read_text().lower()
    assert not re.search(r"\bsecure(ly)?\b", text.replace("not secure", "")), (
        "avoid the word 'secure'"
    )
