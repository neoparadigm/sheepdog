# Security policy

## Reporting a vulnerability or a policy bypass

**Do not open a public issue.** Use GitHub private vulnerability reporting:
`https://github.com/neoparadigm/sheepdog.ai/security/advisories/new

A *policy bypass* (a command that should be denied or asked but is allowed) is a security report
for this project even though the limits are documented in `docs/limitations.md`: we want to fix
it or document it, and add a permanent regression case.

Include: version (`sheepdogai --version`), agent CLI and version, the exact tool call or payload, the
rules in force, and what you expected. Please redact secrets.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (pre-release) | yes, best effort |

## Response timeline

| Step | Target |
|---|---|
| Acknowledge receipt | 3 business days |
| Initial assessment and severity | 7 days |
| Fix or documented mitigation for high severity | 30 days |
| Coordinated public disclosure | after a fix, or 90 days, whichever is first |

These are targets for a volunteer project, not guarantees.

## Safe harbour

If you make a good-faith effort to follow this policy (test only against your own installation,
avoid privacy violations and data destruction, give us reasonable time to fix, do not exploit
beyond what is needed to demonstrate the issue) we will not pursue legal action against you and
will work with you on disclosure and credit.

## Scope

In scope: bypasses of the invariants in `docs/threat-model.md`, daemon/socket permission issues,
log integrity, secret leakage into logs or exports. Out of scope: a malicious user with root, a
compromised machine, an agent CLI that skips its own hooks (see the threat model).
