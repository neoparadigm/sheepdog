# 0008. sheepdogai restricts; it never grants permission

Status: accepted

## Context
Claude Code's hook output `permissionDecision: "allow"` skips the user's own permission prompt.

## Decision
An `allow` verdict is rendered as "no objection": exit 0 and no decision (Claude Code, Codex) or an
empty JSON object (Gemini). The user's normal permission flow still applies. Only `ask` and `deny`
are expressed in a way that changes what happens.

## Consequences
sheepdogai can only make a CLI more cautious than its own settings, never less.
