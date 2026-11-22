# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- Renamed the command, config file (`sheepdogai.yaml`), state folder (`.sheepdogai/`), env vars (`SHEEPDOGAI_*`) and ontology
  prefix from `sheepdog` to `sheepdogai`, to avoid clashing with the `sheepdog` PyPI package and sheepdog.sh. The chat
  commands are `/sheepdogai` and the short `/sheepdog` (never overwrites an existing `/sheepdog` of yours).

Version bumped to 0.1.0 (not yet published).

### Added
- `sheepdogai mcp-server`: sheepdogai's own read-only MCP server (status, recent, dry-run check, verify-log). It has no tool that can change rules, mode or hooks, by design.
- Core contracts (`ToolCallEvent`, `Verdict`, Decider clamp), policy engine with shell normaliser,
  six rule packs, budget guard, redaction, hash-chained log with `verify-log`.
- Adapters for Claude Code and Gemini CLI (verified against official docs); Codex (experimental).
- Unix-socket daemon, thin hook client, `sheepdogai` CLI (init, install/uninstall, hook, status,
  verify-log, graph, replay, conformance, bench).
- Run graph (Mermaid, JSON, JSON-LD), ontology (OWL, JSON-LD context, SHACL) and validation.
- Injection gauntlet corpus v1 and benchmark runner; fuzz, red-team, replay, ontology and perf suites.

- Phase 2: opt-in `personal` pack, approvals (single-use tokens, terminal/ntfy/telegram/webhook
  notifiers), experimental MCP proxy and `wrap()`, static HTML replay report, shared repo config
  (`approve-shared`, tighten-only).

- `sheepdogai setup`: detect agents, show the diff, confirm, install user-wide, self-test; `--undo`.
  User-wide policy at `~/.config/sheepdogai/sheepdogai.yaml` for projects without their own.

- `sheepdogai doctor` (plain-language health check with fix hints) and `sheepdogai recent`.

- `/sheepdogai` chat command (Claude Code skill, Gemini CLI custom command) installed by `setup`; `sheepdogai mode|allow|block`;
  bare `sheepdogai` runs the health check. Tuning commands always ask the human first.

### Fixed
- The wheel no longer ships a top-level `agents` package (it collides with other libraries).

### Security
- Fixed while building (kept as permanent regressions): `curl | sudo bash`, `echo $TOKEN`,
  `/proc/self/environ`, `/etc/shadow`, `ls ~/.ssh`, `~/.git-credentials`, `$IFS$9` word splitting.
