# Threat model

sheepdog is a **guardrail at the tool-call boundary**, not isolation. It reduces the chance that a
confused, prompt-injected or careless-user agent does something destructive. It does not stop a
determined adversary who controls the machine.

## Assets

| Asset | Why it matters |
|---|---|
| The user's files, credentials and keys | Destruction or exfiltration is the main harm. |
| The rules file, hook config and log directory | If the agent can edit them it can switch the guard off or rewrite history. |
| The audit log | Evidence of what the agent did and what was decided. |
| The decision path (adapter, daemon, engine) | A crash or timeout must not become permission. |

## Actors

| Actor | In scope? | Notes |
|---|---|---|
| **Confused agent** (hallucinated or over-eager) | yes | Runs `rm -rf` on the wrong path, force-pushes, edits CI. |
| **Prompt-injected agent** | yes | Untrusted content tells it to exfiltrate, install or disable the guard. |
| **Careless user** | yes | Approves too fast, edits rules wrongly, leaves a rules typo. |
| **Tampered log** | yes | Someone edits, deletes or reorders log records afterwards. |
| Malicious user with root | **out of scope** | They can change anything, including this tool. |
| Compromised machine or kernel | **out of scope** | No integrity guarantee exists below the hook. |
| A CLI that bypasses its own hooks | **out of scope** | If the agent CLI skips hooks (a bug, a flag, a different execution path) sheepdog never sees the call. |
| Another process owned by the same user | out of scope | The daemon socket is owner-only; the same user can already do anything the agent can. |

## Trust boundaries

1. **Agent CLI -> hook process.** The payload is untrusted data (the agent controls tool arguments).
2. **Hook process -> daemon (Unix socket).** Owner-only directory and socket, checked by the
   client on every connect, peer uid checked by the daemon (`SO_PEERCRED` where available).
3. **Daemon -> filesystem.** The log directory is written only by the daemon; the agent's own
   writes to it are denied by `self_protect`.
4. **Rules file -> engine.** Validated at load; invalid rules stop startup or, while running,
   turn every decision into a deny.
5. **Core -> network.** None. Telemetry export is opt-in and lives outside the core packages.

## Threats

| # | Threat | Mitigation | Test |
|---|---|---|---|
| T1 | Daemon down, socket missing, slow or garbage reply turns into allow | Client exits 2 on every failure (all three CLIs treat exit 2 as block) | `tests/unit/test_daemon_failclosed.py` |
| T2 | Malformed or 10 MB payload crashes the hook | Adapters raise only `ParseError`; size cap; fail closed | `tests/conformance/test_adapters.py` |
| T3 | Invalid rules file silently ignored | Strict schema, duplicate/unreachable/ReDoS checks, startup stops with file:line; at runtime deny-all | `tests/unit/test_policy.py`, `test_daemon_failclosed.py` |
| T4 | A model or judge Decider talks the engine into allowing | Decider can only tighten; looser answers are clamped and logged as `decider_violation` | `tests/property/test_engine_properties.py`, `tests/ontology` |
| T5 | Destructive shell command, hidden by obfuscation (quotes, `$'\x72'`, `${IFS}`, base64, subshells, homoglyphs) | Shell normaliser + canonical argv; opaque command words ask | `tests/fuzz/test_fuzz.py`, `tests/redteam` |
| T6 | Path escape with `..` or a symlink | `realpath` before matching; outside-project writes denied | `tests/fuzz/test_fuzz.py`, `tests/unit/test_policy.py` |
| T7 | Secrets exfiltrated over the network | `secrets` pack (path + network use, secret env vars) | `tests/unit/test_gateway_cli.py`, `tests/redteam` |
| T8 | Secrets written to the log | Redaction before hashing; only the redacted form is stored | `tests/unit/test_redact.py`, `tests/unit/test_gateway_cli.py` |
| T9 | Agent edits rules, hook config or logs | `self_protect` runs first and cannot be disabled | `tests/unit/self_protect/` |
| T10 | Log edited, line deleted, reordered or truncated | Hash chain, anchor to policy hash, head sidecar; `verify-log` | `tests/unit/log/test_log.py` |
| T11 | Runaway agent loop | Step, cost and repeat budgets | `tests/unit/test_budget.py` |
| T12 | Injection: risky action after untrusted content | `injection` pack, provenance flag | `tests/redteam`, `tests/unit/test_policy.py` |
| T13 | A CLI that cannot ask is asked to ask | Adapter capabilities; ask is downgraded to deny and logged | `tests/conformance`, `tests/unit/test_matchers.py` |
| T14 | Core code phones home | No network imports in core packages; telemetry opt-in | `tests/unit/test_hygiene.py` |
| T15 | Quadratic or catastrophic-backtracking input | Bounded parser, ReDoS check on rules, size limits | `tests/fuzz/test_fuzz.py` |
| T16 | Policy drift unnoticed | Policy hash in every record; `replay` shows exact verdict diffs | `tests/replay` |

## Residual risk (read `limitations.md`)

Pattern rules can be evaded; hooks do not see everything; tail truncation of the log is only
detectable with the head sidecar or an external anchor. Hooks are guardrails, not isolation:
run untrusted agents in a real sandbox as well.
