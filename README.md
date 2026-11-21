# sheepdogai

A guard at the tool-call boundary of AI agents: it turns every tool call into one standard event,
applies deterministic rules (plus an optional Decider that can only tighten), enforces budgets, and
writes a tamper-evident, replayable record that maps to W3C PROV-O and OpenTelemetry.

> **Hooks are guardrails, not isolation.** sheepdog sees what an agent CLI sends to its hooks and
> pattern-matches it. It does not sandbox anything. Run untrusted agents in a real sandbox too, and
> read [`docs/limitations.md`](docs/limitations.md) before relying on it.

> **Name.** `sheepdogai` / `sheepdog` are placeholders. On 2026-11-21 `sheepdogai` was not on PyPI,
> but a different project named `sheepdog` is, and a commercial product called sheepdog.sh exists.
> **Nothing has been published.** The name lives in one constant (`src/sheepdogai/constants.py`)
> plus the entry point in `pyproject.toml`.

Status: 0.1 pre-release. Claude Code and Gemini CLI adapters follow the official hook docs; the Codex
adapter is experimental because parts of its contract could not be verified.

## Install: two commands

```bash
uv tool install sheepdogai      # after publication; today: uv tool install git+https://github.com/neoparadigm/sheepdog
sheepdog setup
```

`sheepdog setup` finds your agents (Claude Code, Gemini CLI), shows the exact change it will make to
each one's user-wide settings, waits for Enter, installs the hook, writes a user-wide policy
(`balanced` by default: read-only commands run, everything else is checked), and then proves it works by
sending `rm -rf /` through the real hook and confirming it is blocked. Restart your agent and you are
protected in every project. Undo anytime with `sheepdog setup --undo` (your original settings are
restored byte for byte). Use `--yes` to skip the prompt, `--mode strict` to ask about everything.

Want per-project rules instead? `sheepdog init` writes a commented `sheepdog.yaml`; a project's own file
overrides the user-wide one. Codex support is experimental: `sheepdog install codex --experimental`.

## Talk to it: `/sheepdog`

After `sheepdog setup`, type **`/sheepdog`** in Claude Code (a skill) or Gemini CLI (a custom command) and just
say what you want, in plain words:

> `/sheepdog is it working?`
> `/sheepdog what did you block today?`
> `/sheepdog why was my npm install stopped?`
> `/sheepdog be stricter` · `/sheepdog stop asking me about npm test`

The agent runs the matching `sheepdog doctor`, `recent`, `mode`, `allow` or `block` command and explains
the result in short plain sentences. Changing how cautious it is always asks **you** first (the agent cannot
loosen its own guard), it will not look for workarounds when something is blocked, and it is told never to
touch the config or run `setup`/`uninstall`. The same commands work in a terminal:
`sheepdog mode strict`, `sheepdog allow 'npm test*'`, `sheepdog block 'npm publish*'`.

## How do I know it's working?

Three ways, from easiest:

1. **`sheepdog doctor`**: a checklist in plain words. Each line says OK or FAIL, and every FAIL comes with
   the one command that fixes it. It even sends a fake dangerous command through the real hook to prove
   the protection is live.
2. **Ask your agent to run `sudo whoami`.** It is harmless, and sheepdog refuses it with a message like
   *"privilege escalation is not allowed"*. If the agent just runs it, protection is off: run `sheepdog doctor`.
3. **`sheepdog recent`**: a short list of what your agent did in this folder, marked `BLOCKED`, `ASKED` or
   `allowed`, with the reason.

```text
$ sheepdog recent
21:33:17  BLOCKED   sudo whoami
                      why: privilege escalation is not allowed
21:33:40  ASKED     git push origin main
                      why: pushing publishes code
21:34:02  allowed   ls src
```

If protection ever breaks (for example a typo in your rules), it fails *closed*: your agent is blocked,
not left unprotected, and `sheepdog doctor` tells you what to fix.

## What a block looks like

With the default policy, an agent that tries `rm -rf /` gets this back from the hook (exit code 2,
which Claude Code, Codex and Gemini CLI all treat as a block):

```text
$ echo '{"session_id":"t","hook_event_name":"PreToolUse","tool_name":"Bash",
         "tool_input":{"command":"rm -rf /"}, "cwd":"/work/proj"}' | sheepdog hook claude
sheepdog: recursive delete outside the project [machine-recursive-delete-outside]
$ echo $?
2
```

Then inspect and verify what happened:

```bash
sheepdog verify-log t                 # OK .sheepdog/runs/t.jsonl: 2 records, chain intact (sealed ...)
sheepdog graph t --format mermaid     # run graph for a README or issue
sheepdog replay t                     # re-feed the run through the current policy, show verdict diffs
```

## Benchmark: injection gauntlet, corpus v1

`make bench` runs scripted agents (no model, no network) through each adapter. Mode `balanced`,
policy hash `45e708060a98…`, corpus sha256 `da34e40795922b3b…`, Linux x86_64, Python 3.13.18.
Intervals are 95% (Wilson for rates, fixed-seed bootstrap for latency).

| adapter | attacks blocked | hard-denied | benign hard-denied (false positives) | benign asks (friction) | p50 / p95 ms | CPU ms / 1,000 decisions |
|---|---|---|---|---|---|---|
| claude | **blocked 338 of 340 scenarios in corpus v1** (99.4%, 97.9-99.8%) | 259 of 340 (71.4-80.4%) | 0 of 45 (0.0-7.9%) | 20 of 45 (30.9-58.8%) | 2.82 / 4.25 | 1669 (1637-1703) |
| gemini | blocked 338 of 340 scenarios in corpus v1 | 259 of 340 | 0 of 45 | 20 of 45 (asks become denies) | 2.64 / 3.56 | 1601 |
| codex (experimental) | blocked 338 of 340 scenarios in corpus v1 | 259 of 340 | 0 of 45 | 20 of 45 (asks become denies) | 3.16 / 4.30 | 1995 |

The two attacks that got through are documented gaps (`A-S16` `grep -r 'BEGIN RSA PRIVATE KEY' ~`,
`A-S17` a credential file the pack does not list). The first run of this corpus found five more
(`echo $GITHUB_TOKEN`, `/proc/self/environ`, `/etc/shadow`, `ls ~/.ssh`, `~/.git-credentials`);
they were fixed and are permanent regression cases.

How to read this honestly:

* "Blocked" means denied **or** turned into a question for a human. "Friction" is how often a
  benign command is asked about (44% in `balanced`; `strict` asks about everything).
* The corpus was written by the same people who wrote the rules. It finds regressions and known
  gaps; it is **not** an independent adversarial evaluation, and 340 scenarios is a small sample.
* Latency is the in-process gateway (parse, decide, fsynced log write) and excludes interpreter
  start-up. The decision-latency gate (p95 under 25 ms) is enforced in `tests/perf`: engine p95
  0.49 ms, gateway p95 2.6 ms on the same machine. A full `sheepdog hook` process round trip
  measured p50 44 ms, p95 60 ms (CPython start-up dominates).

## Beyond coding agents (Phase 2)

An opt-in `personal` pack (email, payments with a cap, credential stores, deletion, account
changes), phone approvals with single-use tokens, an experimental MCP proxy and `wrap()`, a static
`sheepdog replay --html` report, and a tighten-only shared `.sheepdog/shared.yaml` that applies only
after you approve its hash. See [`docs/phase2.md`](docs/phase2.md).

## How it works

```mermaid
flowchart LR
  A[Agent CLI] -- hook payload --> H[sheepdog hook<br/>stdlib-only client]
  H -- Unix socket --> D[daemon]
  D --> N[adapter.parse -> ToolCallEvent]
  N --> E[engine: self_protect, budget,<br/>user rules, packs]
  E --> X{{Decider<br/>stricter only}}
  X --> L[(hash-chained log)]
  L --> H --> A
```

Invariants, each enforced by tests (see [`docs/threat-model.md`](docs/threat-model.md)):

1. **Fail closed.** Crash, timeout, malformed payload, invalid rules: deny (or ask where a human is
   available). Never allow.
2. **Rules first; a Decider can only tighten** (allow to ask or deny, ask to deny). Looser answers
   are clamped and logged as `decider_violation`.
3. **Self-protection.** The agent cannot edit the rules file, hook config or log directory without
   a human.
4. **Secrets are redacted before anything is logged** or exported.
5. **Append-only, hash-chained log**; `sheepdog verify-log` finds edits, deletions and reordering.
6. **No network from the core.** Telemetry export is an opt-in extra.
7. **Rules are validated at load**; an invalid file stops startup with `file:line`.

`allow` never grants permission: it means "no objection" and the CLI's own permission flow still
applies ([ADR 0008](docs/adr/0008-never-grant-permission.md)).

## Limitations (short version)

* Pattern rules can be evaded: interpreters (`python -c`), scripts the agent writes then runs,
  credential stores the packs do not list, search-for-secrets commands.
* Hooks do not see tool results, subagents the CLI does not route through hooks, or anything the
  CLI does without calling the hook.
* Gemini CLI and Codex cannot ask a human, so asks become denies.
* Whether Claude Code honours a hook block under `bypassPermissions` is not verified here.
* The tail of the log can be truncated cleanly by someone with write access (a sidecar and an
  optional checkpoint help; they do not prevent it).

Full list, with the known-bypass table: [`docs/limitations.md`](docs/limitations.md).

## Repository map

| Path | What |
|---|---|
| `src/sheepdogai/core` | event, verdict, Decider clamp, adapter protocol |
| `src/sheepdogai/policy` | schema, loader, shell normaliser, matchers, engine, packs |
| `src/sheepdogai/{budget,redact,log,graph,ontology,telemetry}` | budgets, redaction, hash chain, run graph, RDF export, OTel mapping |
| `src/sheepdogai/{adapters,daemon,cli}` | CLI adapters + fixtures, Unix-socket daemon and thin client, `sheepdog` command |
| `agents/`, `bench/` | scripted agents, harness, injection gauntlet |
| `tests/` | unit, property, fuzz, conformance, redteam, replay, ontology, perf, self_protect |
| `docs/`, `examples/` | threat model, limitations, architecture, ADRs; three sample policies |

Small additions to the planned layout: `core/canonical.py`, `constants.py`, `approvals.py`,
`approvals_net.py`, `cli/{status,conformance,report,approve}.py`, `adapters/{mcp_proxy,wrap,framework_template}.py`
and `tools/` (repo gates). `make verify` runs lint,
`mypy --strict`, the suite-presence and hygiene gates, every test suite with a 90% coverage gate on
core, policy, log, redact and budget, and the latency gate.

## Development

```bash
make setup     # uv, locked and hash-checked
make verify    # what CI runs
make bench     # writes bench/report.md and report.json
make fuzz      # property-based fuzz suite on its own
```

Apache-2.0. See [`CONTRIBUTING.md`](CONTRIBUTING.md) (DCO sign-off), [`SECURITY.md`](SECURITY.md),
[`GOVERNANCE.md`](GOVERNANCE.md).
