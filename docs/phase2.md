# Phase 2: personal agents, MCP proxy, approvals, reports, shared config

All of this reuses the same core (events, engine, log, replay) and keeps the invariants: fail
closed, a Decider can only tighten, no network from the core.

## Personal rule pack (`personal`, opt-in)

Noisy for coding agents, so it is not in the default pack list. List it **before** `secrets`
(first match wins) and set its knobs under `settings:` (see `examples/personal.yaml`).

| Rule | Outcome |
|---|---|
| password managers, browser profiles and cookie stores, keychains, wallets, `~/.ssh`: read or write | deny |
| the same, sent over the network | deny |
| public post (social, public paste, public repo, public gist) | ask, **every time** (`once_only`) |
| payment, purchase, transfer, subscription | ask every time; **deny above `settings.payment_cap_usd`** |
| share a document publicly; change account settings, permissions or recovery details | ask every time |
| bulk delete (many targets, wildcard, recursive) | deny |
| delete or move outside `settings.delete_allowlist` | ask |
| email, message or invite to anyone not in `settings.own_addresses` (or when the recipient cannot be determined) | ask |

The pack also lowers the default budget (60 steps, $2, 2 repeats) unless you set `budget:`.
Tool names are matched by glob (`*send_email*`); adapt them to your agent. `tests/unit/test_personal_pack.py`
holds an allowed, asked or denied fixture for every rule.

## Approvals

`ask` becomes three answers: **deny**, **allow once**, **allow for this run** (never offered for
`once_only` rules). Set `approvals.channel` to `cli` (default: the agent CLI's own prompt where it
has one), `terminal`, `ntfy`, `telegram` or `webhook`.

* Each approval is a **single-use token bound to the event hash and an expiry**. A replayed token, an
  expired token, a token for a different event, a forged token, or an allow without a valid token is a
  deny. A **timeout is a deny**, and a late answer is useless.
* The agent can never read or answer one: tokens live in daemon memory and the channel to the
  human; the HMAC key is `0600`; `self_protect` denies any access to `.sheepdog/approval*`,
  `.sheepdog/approved/` and `~/.config/<cli>/`, and denies running `sheepdog approve*`.
* Every approval is logged as a `HumanApproval` (`outcome`: `allow_once`, `allow_run`, `denied`,
  `timeout_deny`; `channel`). The token itself is never logged.
* With a human channel configured, Gemini CLI and Codex (which cannot ask) can still get approvals:
  the engine asks, the phone answers, the CLI only ever sees allow or deny.
* Network notifiers read credentials from `~/.config/<cli>/notify.json` (must be mode 0600), not from
  the environment. They are experimental and tested only against local mock servers; the ntfy and
  Telegram wire formats are not verified against the live services.
* **Timeout budget:** the hook client waits `SHEEPDOG_TIMEOUT_S` (default 5 s) for the daemon. For a
  remote channel set it above `approvals.ask_timeout_s`, otherwise the hook times out first and
  denies (safe, but you never get to answer). `sheepdog status` warns about this.

## MCP proxy and `wrap()` (experimental)

`sheepdog mcp-proxy --name github -- <server command>` sits between an agent and any MCP server
over stdio. `tools/list` and everything else pass through; each `tools/call` becomes one event
(`mcp__<name>__<tool>`), goes through the same engine, and is forwarded or answered with an
`isError` tool result that names the rule. Daemon unreachable: refused. Results are never rewritten
except for secret redaction. Batched `tools/call` is refused. For frameworks with neither hooks nor MCP:
`sheepdogai.wrap(tool)` raises `ToolBlocked` instead of calling the tool unless the verdict is allow.
Both pass the shared conformance suite and stay marked experimental in v0.1.

## Shareable replay report

`sheepdog replay <run> --html report.html` writes one static file: verdict timeline, denied and
asked calls, all calls, and the run graph as Mermaid source. No scripts, no external resources,
a `default-src 'none'` Content-Security-Policy, secrets re-redacted, HTML-escaped, mode 0600; the
same log gives the same bytes (tested in-process and across processes).

## Shared repo config

A committed `.sheepdog/shared.yaml` is merged **under** your own config and can only tighten: a
stricter `mode`, extra packs, lower budgets, and `ask`/`deny` rules (prefixed `shared.`, after
yours, before packs). It is untrusted: it takes effect only after you approve its sha256
(`sheepdog approve-shared`; the agent cannot run that command or write the approval), and any
change to the file needs approval again. `sheepdog approve-shared` refuses to approve a file that
tries to loosen anything (allow rules, a looser mode, higher budgets, or the keys `fail`,
`decider`, `log`, `approvals`, `settings`). `sheepdog status` shows its state.
