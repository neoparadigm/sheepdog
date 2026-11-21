# Contributing

1. `make setup` (uses `uv`, locked and hash-checked), then `make verify` must pass.
2. **Tests first.** Every behaviour change comes with a test. A bypass fix also adds a case to
   `tests/redteam/regressions.yaml` (never delete one).
3. Keep dependencies minimal. A new one needs an ADR (`docs/adr/0007-dependencies.md`).
4. Do not claim what you cannot measure. Do not invent facts about external tools: link the
   official doc, save a real payload as a fixture, and mark what you could not verify with the
   word `UNVERIFIED` and an experimental flag (it may appear only in experimental adapters, docs
   and tests; `tools/check_hygiene.py` enforces this).
5. Never write the word "secure" in marketing text. Say what was measured.

## Commit sign-off (DCO)

Every commit must carry a `Signed-off-by` line certifying the
[Developer Certificate of Origin](https://developercertificate.org/): `git commit -s`.

## Changing the golden run

Changing a pack or the schema changes the policy hash, so the golden run in
`tests/replay/golden/` must be regenerated: `uv run python tools/make_golden.py`. Review the diff.
