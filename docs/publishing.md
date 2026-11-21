# Publishing to PyPI (maintainers)

Nothing is published automatically. The release workflow (`.github/workflows/release.yml`) runs on a
`v*` tag, builds the sdist and wheel, writes a CycloneDX SBOM, signs with Sigstore, and publishes through
**PyPI trusted publishing** (no API token is stored anywhere).

One-time setup, by the project owner:

1. Create a PyPI account (with 2FA) and, on PyPI, **Add a pending publisher** (Account > Publishing):
   project name `sheepdogai`, owner `neoparadigm`, repository `sheepdog`, workflow `release.yml`,
   environment `pypi`.
2. In GitHub, repository Settings > Environments: create `pypi` (optionally require a reviewer).
3. Make sure the name is what you want: **a PyPI name cannot be renamed or reclaimed later.** An
   unrelated project called `sheepdog` already exists on PyPI, and sheepdog.sh is a commercial product;
   the console command is also called `sheepdog`, which would collide with that project's scripts if both
   are installed in the same environment.
4. Update the placeholders (`security@example.invalid`, `conduct@example.invalid`).
5. Optionally dry-run first on TestPyPI by pointing a copy of the workflow at `repository-url:
   https://test.pypi.org/legacy/`.

Release:

```bash
make verify                      # must pass
git tag v0.1.0 && git push origin v0.1.0
```

Check the Actions run, then in a clean machine: `uv tool install sheepdogai && sheepdog setup && sheepdog doctor`.
The `release` job's publish step fails (safely) until step 1 is done.
