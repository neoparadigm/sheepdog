from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def short_tmp() -> Iterator[Path]:
    """A short temp dir (Unix socket paths are limited to ~104 bytes)."""
    d = Path(tempfile.mkdtemp(prefix="sd", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def runtime(short_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    rt = short_tmp / "rt"
    rt.mkdir(mode=0o700)
    monkeypatch.setenv("SHEEPDOGAI_RUNTIME_DIR", str(rt))
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.delenv("SHEEPDOGAI_PROJECT", raising=False)
    return rt


@pytest.fixture
def project(short_tmp: Path) -> Path:
    p = short_tmp / "proj"
    p.mkdir()
    os.chmod(p, 0o755)
    return p


@pytest.fixture(autouse=True)
def _isolated_home(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Never let a developer's real ~/.config/<tool>/ policy (or ~/.claude) leak into a test."""
    h = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(h))
