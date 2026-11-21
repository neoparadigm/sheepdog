import pytest

from sheepdogai.redact.secrets import redact_obj, redact_text

CASES = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_" + "a" * 36,
    "github_pat_" + "A1b2" * 10,
    "xoxb-1234567890-abcdefghij",
    "sk-" + "x" * 30,
    "Authorization: Bearer abcdefghijklmnopqrstuvwx",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk",
    "https://user:hunter2hunter2@example.com/x",
    "export API_KEY=supersecretvalue",
    "password: 'p@ss w0rd'",
]


@pytest.mark.parametrize("s", CASES)
def test_redacts_and_idempotent(s: str) -> None:
    out = redact_text(s)
    assert "[REDACTED" in out
    assert redact_text(out) == out


def test_private_key_block_and_unterminated() -> None:
    k = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----"
    assert "MIIEabc" not in redact_text(f"cat <<E\n{k}\nE")
    assert "MIIEabc" not in redact_text("-----BEGIN PRIVATE KEY-----\nMIIEabc")


def test_obj_sensitive_keys_and_nesting() -> None:
    o = redact_obj({"headers": {"Authorization": "x y z"}, "l": ["ok", {"password": "p"}]})
    assert o["headers"]["Authorization"].startswith("[REDACTED")
    assert o["l"][1]["password"].startswith("[REDACTED") and o["l"][0] == "ok"


def test_benign_text_untouched() -> None:
    assert redact_text("git status && ls -la") == "git status && ls -la"


def test_huge_string_is_linear_and_truncated() -> None:
    out = redact_text("a" * 3_000_000)
    assert len(out) < 1_100_000 and "TRUNCATED" in out
