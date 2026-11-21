# sheepdogai

A safety and observability gate at the tool-call boundary of AI agents. For every tool call it
normalises the request into one event, applies deterministic rules (and an optional Decider that
can only tighten), enforces budgets, and writes a tamper-evident, replayable record.

**Hooks are guardrails, not isolation.** Start with [limitations](limitations.md) and the
[threat model](threat-model.md).
