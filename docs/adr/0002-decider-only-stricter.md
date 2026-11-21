# 0002. A Decider can only make a verdict stricter

Status: accepted

## Context
A model or judge may add judgement the rules lack, but a model can be manipulated by the same
untrusted content that manipulates the agent.

## Decision
Order is allow < ask < deny. Deterministic rules always run first. The engine wraps every Decider
(`apply_decider_ex`): a looser answer is replaced by the rules verdict and logged as
`decider_violation`; a crash or non-Verdict becomes deny (`decider_error`). The run graph records
the rules verdict, the Decider's raw proposal and a `priorVerdict` link, and a SHACL shape rejects
any graph where a Decider verdict is less strict than the rules verdict it received.

## Consequences
A compromised judge can cause extra friction but cannot unlock a denied action. `local_model` and
`llm_judge` are not implemented in v0.1; selecting them stops startup rather than being ignored.
