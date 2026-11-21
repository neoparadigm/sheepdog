# 0003. Hooks first, MCP proxy later

Status: accepted

## Context
Two integration points exist: the agent CLI's own tool hooks, and an MCP proxy between agent and
MCP server.

## Decision
v0.1 integrates through CLI hooks. They see built-in tools (shell, file edits) that an MCP proxy
never would, and need no change to the agent's configuration beyond one hook entry. An MCP proxy
(`adapters/mcp_proxy.py`) is added in Phase 2 as an *experimental* adapter that reuses the same
engine.

## Consequences
Coverage depends on what each CLI exposes to hooks (see `limitations.md`). Hooks are not a
sandbox.
