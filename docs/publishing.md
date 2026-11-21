# Publishing to PyPI (maintainers)

Nothing is published automatically. The release workflow (`.github/workflows/release.yml`) runs on a
`v*` tag, builds the sdist and wheel, writes a CycloneDX SBOM, signs with Sigstore, and publishes through
**PyPI trusted publishing** (no API token is stored anywhere).

One-time setup, by the project owner:

1. Create a PyPI account (with 2FA) and, on PyPI, **Add a pending publisher** (Account > Publishing):
   project name `sheepdogai`, owner `neoparadigm`, repository `sheepdogai` (rename the GitHub repo from `sheepdog` first), workflow `release.yml`,
   environment `pypi`.
2. In GitHub, repository Settings > Environments: create `pypi` (optionally require a reviewer).
3. Make sure the name is what you want: **a PyPI name cannot be renamed or reclaimed later.** The command is
   `sheepdogai` precisely to avoid colliding with the unrelated `sheepdog` PyPI package and the sheepdog.sh product.
4. Update the placeholders (`security@example.invalid`, `conduct@example.invalid`).
5. Optionally dry-run first on TestPyPI by pointing a copy of the workflow at `repository-url:
   https://test.pypi.org/legacy/`.

Release:

```bash
make verify                      # must pass
git tag v0.1.0 && git push origin v0.1.0
```

Check the Actions run, then in a clean machine: `uv tool install sheepdogai && sheepdogai setup && sheepdogai doctor`.
The `release` job's publish step fails (safely) until step 1 is done.

## OpenSSF Scorecard findings (what is and is not fixable in code)

| Check | Why it is open | What to do |
|---|---|---|
| Fuzzing | Scorecard does not count Python property-based testing (Hypothesis). It counts OSS-Fuzz, ClusterFuzzLite, Go fuzzing and a few other languages. | Done in code: `fuzz/fuzz_policy.py` + `.clusterfuzzlite/` + `cflite_pr.yml` (untested config). |
| Maintained | Needs at least one commit per week for 90 days; the repo is new. | Nothing to do but keep committing; it improves by itself. |
| Branch-Protection | A GitHub setting. | Settings > Rules > Rulesets: protect `main`: require a pull request, require status checks (`verify`, `docs`), block force pushes and deletion. |
| Code-Review | Needs changes to land through pull requests that someone other than the author approved. A single maintainer cannot honestly satisfy this. | Add a second reviewer, then require 1 approval in the same ruleset. |
| CII-Best-Practices | A badge you apply for. | Register at https://www.bestpractices.dev and answer the questionnaire (many answers are already true here: license, SECURITY.md, CI, tests). |
