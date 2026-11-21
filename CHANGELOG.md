# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Core contracts (`ToolCallEvent`, `Verdict`, Decider clamp), policy engine with shell normaliser,
  six rule packs, budget guard, redaction, hash-chained log with `verify-log`.
- Adapters for Claude Code and Gemini CLI (verified against official docs); Codex (experimental).
- Unix-socket daemon, thin hook client, `sheepdog` CLI (init, install/uninstall, hook, status,
  verify-log, graph, replay, conformance, bench).
- Run graph (Mermaid, JSON, JSON-LD), ontology (OWL, JSON-LD context, SHACL) and validation.
- Injection gauntlet corpus v1 and benchmark runner; fuzz, red-team, replay, ontology and perf suites.

- Phase 2: opt-in `personal` pack, approvals (single-use tokens, terminal/ntfy/telegram/webhook
  notifiers), experimental MCP proxy and `wrap()`, static HTML replay report, shared repo config
  (`approve-shared`, tighten-only).

### Security
- Fixed while building (kept as permanent regressions): `curl | sudo bash`, `echo $TOKEN`,
  `/proc/self/environ`, `/etc/shadow`, `ls ~/.ssh`, `~/.git-credentials`, `$IFS$9` word splitting.
