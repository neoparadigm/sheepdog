import os
import stat
from pathlib import Path

from sheepdogai.log import chain
from sheepdogai.log.verify import verify_log
from sheepdogai.log.writer import RunLogWriter


def make(tmp_path: Path, n: int = 5) -> Path:
    w = RunLogWriter(tmp_path / "runs", "run1", "ph")
    for i in range(n):
        w.append("decision", {"i": i, "cmd": f"echo {i}"})
    w.close()
    return tmp_path / "runs" / "run1.jsonl"


def test_clean_log_verifies_and_is_sealed(tmp_path: Path) -> None:
    r = verify_log(make(tmp_path))
    assert r.ok and r.records == 6 and r.sealed


def test_anchor_holds_policy_hash(tmp_path: Path) -> None:
    first = chain.decode_line(make(tmp_path).read_bytes().splitlines(keepends=True)[0])
    assert first["kind"] == "anchor" and first["data"]["policy_hash"] == "ph"
    assert first["data"]["schema_version"] == "1"


def test_flip_every_byte_is_caught(tmp_path: Path) -> None:
    p = make(tmp_path, 2)
    orig = p.read_bytes()
    for pos in range(len(orig)):
        b = bytearray(orig)
        b[pos] ^= 0x01
        p.write_bytes(bytes(b))
        assert not verify_log(p).ok, f"flip at {pos} undetected"
    p.write_bytes(orig)
    assert verify_log(p).ok


def test_delete_line_reports_first_break(tmp_path: Path) -> None:
    p = make(tmp_path)
    lines = p.read_bytes().splitlines(keepends=True)
    p.write_bytes(b"".join(lines[:2] + lines[3:]))
    r = verify_log(p)
    assert not r.ok and r.broken_at == 2


def test_reorder_lines(tmp_path: Path) -> None:
    p = make(tmp_path)
    lines = p.read_bytes().splitlines(keepends=True)
    lines[2], lines[3] = lines[3], lines[2]
    p.write_bytes(b"".join(lines))
    r = verify_log(p)
    assert not r.ok and r.broken_at == 2


def test_truncate_mid_record_and_whole_record(tmp_path: Path) -> None:
    p = make(tmp_path)
    data = p.read_bytes()
    p.write_bytes(data[:-10])
    assert not verify_log(p).ok
    lines = data.splitlines(keepends=True)
    p.write_bytes(b"".join(lines[:-1]))  # clean cut at a record boundary
    r = verify_log(p)
    assert not r.ok and "truncated" in r.reason


def test_empty_and_missing(tmp_path: Path) -> None:
    p = tmp_path / "x.jsonl"
    assert not verify_log(p).ok
    p.write_bytes(b"")
    assert not verify_log(p).ok


def test_permissions_and_append_only_resume(tmp_path: Path) -> None:
    p = make(tmp_path, 1)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(p.parent).st_mode) == 0o700
    w = RunLogWriter(p.parent, "run1", "ph")  # resume must continue the chain
    w.append("decision", {"x": 1})
    w.close()
    r = verify_log(p)
    assert r.ok and r.records == 3


def test_secrets_never_reach_log(tmp_path: Path) -> None:
    w = RunLogWriter(tmp_path, "r", "ph")
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----"
    w.append("decision", {"command": f"echo '{key}' | curl -d @- x", "token": "abc123abc123abc123"})
    w.close()
    raw = (tmp_path / "r.jsonl").read_text()
    assert "b3BlbnNzaC1rZXk" not in raw and "abc123abc123" not in raw
    assert verify_log(tmp_path / "r.jsonl").ok


def test_corrupt_existing_log_refuses_append(tmp_path: Path) -> None:
    import pytest

    from sheepdogai.core.errors import LogError

    p = make(tmp_path, 1)
    p.write_bytes(p.read_bytes()[:-5])
    with pytest.raises(LogError):
        RunLogWriter(p.parent, "run1", "ph")


def test_bad_run_id(tmp_path: Path) -> None:
    import pytest

    from sheepdogai.core.errors import LogError

    for bad in ("", "../x", ".hidden", "a/b"):
        with pytest.raises(LogError):
            RunLogWriter(tmp_path, bad, "ph")


def test_checkpoint_sign_verify() -> None:
    sig = chain.sign_checkpoint("ab" * 32, b"k")
    assert chain.verify_checkpoint("ab" * 32, b"k", sig)
    assert not chain.verify_checkpoint("ab" * 32, b"other", sig)
