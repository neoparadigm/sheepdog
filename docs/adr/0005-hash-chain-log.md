# 0005. Hash-chained, append-only JSON Lines log

Status: accepted

## Decision
One JSON Lines file per run, written with `O_APPEND` and `fsync`, mode 0600 in a 0700 directory.
`hash = sha256(prev_hash || canonical_json(record))`; the first record anchors to the policy hash
and schema version. Secrets are redacted **before** hashing; only the redacted form is stored.
`verify-log` recomputes the chain and reports the first broken record. A `.head` sidecar and an
optional HMAC checkpoint address clean tail truncation, which a chain alone cannot detect.

## Consequences
Edits, deletions and reordering are detectable. A user who can write the log directory can still
truncate cleanly and rewrite the sidecar; see `limitations.md`. Long strings are shortened with a
digest, so replay of very long arguments may be inexact and says so.
