# 0001. Fail closed

Status: accepted

## Context
A hook runs on every tool call. Three of its failure modes are common: the daemon is not running,
the payload is malformed, the rules file is broken. Claude Code treats a hook that exits 0 with
unparseable output, or exits with any code other than 0 or 2, as a *non-blocking* error and lets the
call proceed (https://code.claude.com/docs/en/hooks). Codex does the same for exit codes other than
0 and 2 (see the adapter docstring). Gemini treats other exit codes as warnings.

## Decision
Every failure path produces **exit 2 with a non-empty reason on stderr**, which all three CLIs
treat as a block. This includes client exceptions (even `KeyboardInterrupt`), daemon timeouts,
unsafe socket permissions, malformed payloads, internal engine errors and log write failures.
`fail:` in `sheepdogai.yaml` accepts only `closed`; an `unsafe_` prefix is reserved and not implemented.
An invalid rules file stops daemon startup (error with file and line); if it becomes invalid while
running, every call is denied until it is fixed.

## Consequences
Outages are loud: a broken setup blocks the agent instead of silently disabling the guard. Users
who want less friction change `mode`, not `fail`. Tested by the fail-closed matrix.
