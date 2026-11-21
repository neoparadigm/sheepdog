# 0009. Approvals are single-use and out of the agent's reach; shared config is untrusted

Status: accepted

## Context
Phase 2 adds human approval from a phone and a committed, team-wide config. Both are places where the
agent (or a hostile repository) could try to grant itself permission.

## Decision
* An approval is a **single-use token bound to the event hash and an expiry**, minted by the daemon,
  held in memory and sent only to the human's channel. Timeout, replay, expiry, wrong event, forged
  or missing token: deny. Only `allow_once` and `allow_run` exist; `once_only` rules never accept
  `allow_run`. The token is never logged; the outcome and channel are.
* The HMAC key, used-nonce file, approval directory and notifier credentials
  (`~/.config/<cli>/`) are denied to the agent by `self_protect`, as is running `approve`.
* `.sheepdogai/shared.yaml` is data, not code: it applies only when its sha256 equals a hash the human
  approved, it can only tighten (stricter mode, more packs, lower budgets, ask/deny rules), and a
  loosening file is rejected at approval time and again at load.
* Network notifiers live outside the core (`approvals_net`), read credentials from a 0600 file, and
  accept only http(s) URLs.

## Consequences
A compromised agent cannot approve itself, and a malicious pull request cannot silently relax the
policy. Approvals through a remote channel need the hook timeout raised (documented, and `status`
warns).
