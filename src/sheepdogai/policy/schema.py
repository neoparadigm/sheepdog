"""Pydantic schema for sheepdogai.yaml and rule packs. Unknown keys are rejected."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Strs = str | list[str]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProvenanceMatch(_Strict):
    """Match on provenance flags."""

    untrusted_content_seen: bool | None = None


class BudgetMatch(_Strict):
    """Match on budget counters (strictly greater than)."""

    steps_gt: int | None = None
    cost_gt: float | None = None
    repeats_gt: int | None = None


class Match(_Strict):
    """All given matchers must hold (AND). Lists inside a matcher are OR.

    ``command`` and ``path`` and ``domain`` take globs; prefix a command with ``re:`` for a
    regex. The last block of fields are derived facts computed from the normalised event.
    """

    tool: Strs | None = None
    kind: Strs | None = None
    command: Strs | None = None
    path: Strs | None = None
    domain: Strs | None = None
    domain_not: Strs | None = None  # matches when some host is outside this allowlist
    provenance: ProvenanceMatch | None = None
    budget: BudgetMatch | None = None
    # derived facts
    outside_project: bool | None = None
    mutates: bool | None = None
    network_use: bool | None = None
    pipe_to_shell: bool | None = None
    opaque: bool | None = None
    secret_env: bool | None = None
    amount_gt: float | None = None
    amount_over_cap: bool | None = None  # amount > settings.payment_cap_usd
    recipient_external: bool | None = None
    outside_allowlist: bool | None = None  # target not inside settings.delete_allowlist
    bulk: bool | None = None  # many targets, a wildcard or a recursive flag


class Rule(_Strict):
    """One rule: id, match, action, reason."""

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
    match: Match
    action: Literal["allow", "ask", "deny"]
    reason: str = ""
    once_only: bool = False  # approvals for this rule are never remembered for the run

    @field_validator("match")
    @classmethod
    def _non_empty(cls, m: Match) -> Match:
        if not m.model_dump(exclude_none=True):
            raise ValueError("match must have at least one matcher")
        return m


class BudgetConfig(_Strict):
    """Budget limits."""

    max_steps: int = Field(200, ge=1)
    max_cost_usd: float = Field(5.0, ge=0)
    max_repeats: int = Field(3, ge=1)


class ApprovalsConfig(_Strict):
    """Human approval settings."""

    ask_timeout_s: int = Field(60, ge=1, le=3600)
    remember: Literal["none", "session", "run"] = "session"
    channel: Literal["cli", "terminal", "ntfy", "telegram", "webhook"] = "cli"


class LogConfig(_Strict):
    """Log settings. Hash chaining and redaction cannot be turned off in v0.1."""

    path: str = ".sheepdogai/runs"
    hash_chain: Literal[True] = True
    redact_secrets: Literal[True] = True


class DeciderConfig(_Strict):
    """Which Decider to use after the rules."""

    type: str = "rules"

    @field_validator("type")
    @classmethod
    def _known(cls, v: str) -> str:
        if v in {"rules", "local_model", "llm_judge"} or v.startswith("python:"):
            return v
        raise ValueError(
            "decider.type must be rules | python:<module>:<class> | local_model | llm_judge"
        )


class PackSettings(_Strict):
    """Per-pack knobs used by the personal pack."""

    payment_cap_usd: float = 50.0
    delete_allowlist: list[str] = Field(default_factory=list)
    own_addresses: list[str] = Field(default_factory=list)
    scratch_paths: list[str] = Field(
        default_factory=lambda: ["/tmp", "/var/tmp", "/private/tmp", "/private/var/folders"]
    )


class Config(_Strict):
    """Top-level sheepdogai.yaml."""

    version: Literal[1]
    mode: Literal["strict", "balanced", "relaxed"] = "strict"
    fail: str = "closed"
    packs: list[str] = Field(
        default_factory=lambda: [
            "self_protect",
            "machine",
            "secrets",
            "repo",
            "network",
            "injection",
        ]
    )
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    approvals: ApprovalsConfig = Field(default_factory=ApprovalsConfig)
    log: LogConfig = Field(default_factory=LogConfig)
    decider: DeciderConfig = Field(default_factory=DeciderConfig)
    settings: PackSettings = Field(default_factory=PackSettings)
    rules: list[Rule] = Field(default_factory=list)

    @field_validator("fail")
    @classmethod
    def _closed_only(cls, v: str) -> str:
        if v != "closed":
            raise ValueError(
                "fail: only 'closed' is supported (an explicit unsafe_ prefix is reserved and "
                "not implemented in v0.1)"
            )
        return v


class PackFile(_Strict):
    """A rule pack on disk."""

    name: str
    description: str = ""
    defs: dict[str, Any] = Field(default_factory=dict)  # YAML anchors live here
    budget: BudgetConfig | None = None
    rules: list[Rule]


class SharedConfig(_Strict):
    """Committed .sheepdogai/shared.yaml. Untrusted; it can only tighten the user's own config."""

    version: Literal[1]
    mode: Literal["strict", "balanced", "relaxed"] | None = None
    packs: list[str] = Field(default_factory=list)
    budget: BudgetConfig | None = None
    rules: list[Rule] = Field(default_factory=list)
