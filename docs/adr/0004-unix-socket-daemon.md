# 0004. A local daemon behind a Unix socket

Status: accepted

## Context
A hook process starts for every tool call. Python start-up plus loading pydantic, YAML and compiling
every rule on each call would dominate latency.

## Decision
A thin client (standard library only) forwards the payload over a Unix socket to a per-project
daemon that keeps the policy loaded. The socket directory is 0700 and owned by the user; the client
refuses a socket that is not owner-only and the daemon checks the peer uid. The daemon never
executes payload content or shells out with payload strings. It starts on demand and exits after
idle time.

## Consequences
Warm decisions are sub-millisecond in the engine (see `tests/perf`). A process-start cost remains
for the hook itself. Windows is unsupported in v0.1.
