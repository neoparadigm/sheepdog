"""Load and validate sheepdogai.yaml and rule packs. Any problem raises RulesError (fail closed)."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from sheepdogai.constants import CLI_NAME, CONFIG_FILE, STATE_DIR
from sheepdogai.core.canonical import canonical_json, sha256_hex
from sheepdogai.core.errors import RulesError
from sheepdogai.policy.matchers import CompiledMatch, check_regex_safe
from sheepdogai.policy.schema import BudgetConfig, Config, Match, PackFile, Rule, SharedConfig

BUILTIN_PACKS = ("self_protect", "machine", "secrets", "repo", "network", "injection", "personal")
ALWAYS_FIRST = "self_protect"
SHARED_REL = f"{STATE_DIR}/shared.yaml"
APPROVED_REL = f"{STATE_DIR}/approved/shared.sha256"
MODE_RANK = {"relaxed": 0, "balanced": 1, "strict": 2}


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""


def _construct_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> Any:
    seen: set[Any] = set()
    for k, _ in node.value:
        key = loader.construct_object(k, deep=True)
        if key in seen:
            raise RulesError(f"duplicate key {key!r}", line=k.start_mark.line + 1)
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


@dataclass(frozen=True)
class LoadedRule:
    """A validated rule with provenance (which pack or file it came from)."""

    rule: Rule
    origin: str
    line: int | None
    compiled: CompiledMatch


@dataclass
class Policy:
    """A fully loaded, validated, hashed policy."""

    config: Config
    rules: list[LoadedRule]
    policy_hash: str
    project_root: str
    home: str
    source: str
    budget: BudgetConfig
    notes: list[str] = field(default_factory=list)


def _line_of(node: yaml.Node | None) -> int | None:
    return None if node is None else node.start_mark.line + 1


def _locate(root: yaml.Node | None, loc: tuple[Any, ...]) -> int | None:
    node = root
    for part in loc:
        if isinstance(node, yaml.MappingNode):
            nxt = None
            for k, v in node.value:
                if getattr(k, "value", None) == part:
                    nxt = v
                    if len(loc) == 1 or part == loc[-1]:
                        return _line_of(k)
                    break
            if nxt is None:
                return _line_of(node)
            node = nxt
        elif (
            isinstance(node, yaml.SequenceNode) and isinstance(part, int) and part < len(node.value)
        ):
            node = node.value[part]
        else:
            break
    return _line_of(node)


def parse_yaml(text: str, file: str) -> tuple[dict[str, Any], yaml.Node | None]:
    """Parse YAML safely with duplicate-key detection; returns (data, root node)."""
    try:
        root = yaml.compose(text, Loader=_UniqueKeyLoader)
        loader = _UniqueKeyLoader(text)
        try:
            data = loader.get_single_data()  # what yaml.safe_load does, on our SafeLoader subclass
        finally:
            loader.dispose()
    except RulesError as e:
        raise RulesError(str(e).split(": ", 1)[-1], file=file, line=e.line) from e
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        raise RulesError(
            f"invalid YAML: {getattr(e, 'problem', e)}",
            file=file,
            line=None if mark is None else mark.line + 1,
        ) from e
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise RulesError("top level must be a mapping", file=file, line=1)
    return data, root


def _validate(model: Any, data: dict[str, Any], root: yaml.Node | None, file: str) -> Any:
    try:
        return model.model_validate(data)
    except ValidationError as e:
        err = e.errors()[0]
        loc = tuple(err["loc"])
        raise RulesError(
            f"{'.'.join(map(str, loc))}: {err['msg']}", file=file, line=_locate(root, loc)
        ) from e


def _covers(a: Match, b: Match) -> bool:
    """True when every event matched by ``b`` is certainly matched by ``a`` (a is broader)."""
    da, db = a.model_dump(exclude_none=True), b.model_dump(exclude_none=True)
    for k, va in da.items():
        if k not in db:
            return False
        vb = db[k]
        if k in {"tool", "kind"}:
            sa = {x.lower() for x in ([va] if isinstance(va, str) else va)}
            sb = {x.lower() for x in ([vb] if isinstance(vb, str) else vb)}
            if not sb <= sa:
                return False
        elif k in {"command", "path", "domain"}:
            la = [va] if isinstance(va, str) else list(va)
            lb = [vb] if isinstance(vb, str) else list(vb)
            for x in lb:
                if not any(
                    x == g
                    or (
                        not g.startswith("re:")
                        and not x.startswith("re:")
                        and fnmatch.fnmatchcase(" ".join(x.split()), " ".join(g.split()))
                    )
                    for g in la
                ):
                    return False
        elif va != vb:
            return False
    return True


def check_rules(rules: list[Rule], lines: list[int | None], file: str, shadow: bool = True) -> None:
    """Reject duplicate ids, unsafe regexes and rules shadowed by an earlier one."""
    seen: dict[str, int | None] = {}
    for i, r in enumerate(rules):
        if r.id in seen:
            raise RulesError(
                f"duplicate rule id {r.id!r} (first at line {seen[r.id]})", file, lines[i]
            )
        seen[r.id] = lines[i]
        for c in [r.match.command] if isinstance(r.match.command, str) else r.match.command or []:
            if c.startswith("re:"):
                bad = check_regex_safe(c[3:])
                if bad:
                    raise RulesError(f"rule {r.id!r}: unsafe regex {c!r}: {bad}", file, lines[i])
        for j in range(i if shadow else 0):
            if _covers(rules[j].match, r.match):
                raise RulesError(
                    f"rule {r.id!r} is unreachable: shadowed by earlier rule {rules[j].id!r} "
                    f"(line {lines[j]})",
                    file,
                    lines[i],
                )


def load_pack(name: str) -> tuple[PackFile, list[int | None]]:
    """Load one built-in pack by name."""
    if name not in BUILTIN_PACKS:
        raise RulesError(f"unknown pack {name!r}; built-in packs: {', '.join(BUILTIN_PACKS)}")
    file = f"packs/{name}.yaml"
    text = resources.files("sheepdogai.policy.packs").joinpath(f"{name}.yaml").read_text("utf-8")
    text = (
        text.replace("{cli}", CLI_NAME)
        .replace("{ENV}", CLI_NAME.upper())
        .replace("{state}", STATE_DIR)
        .replace("{config_alt}", CONFIG_FILE.replace(".yaml", ".yml"))
        .replace("{config}", CONFIG_FILE)
    )
    data, root = parse_yaml(text, file)
    pack = _validate(PackFile, data, root, file)
    lines: list[int | None] = []
    if isinstance(root, yaml.MappingNode):
        for k, v in root.value:
            if k.value == "rules" and isinstance(v, yaml.SequenceNode):
                lines = [_line_of(n) for n in v.value]
    lines = lines or [None] * len(pack.rules)
    check_rules(pack.rules, lines, file)
    return pack, lines


def build_policy(
    config: Config,
    *,
    project_root: str,
    home: str | None = None,
    source: str = "<default>",
    user_lines: list[int | None] | None = None,
    shared: SharedConfig | None = None,
    shared_lines: list[int | None] | None = None,
) -> Policy:
    """Compile a validated config + packs (+ an approved shared config) into a Policy."""
    home = home or os.path.expanduser("~")
    project_root = os.path.realpath(project_root)
    user_config = config
    if shared is not None:
        config = merge_shared(user_config, shared)
    names = list(dict.fromkeys(config.packs))
    notes: list[str] = []
    if ALWAYS_FIRST in names:
        names.remove(ALWAYS_FIRST)
    else:
        notes.append("self_protect was not listed in packs; it is always enabled")
    names.insert(0, ALWAYS_FIRST)
    user_lines = user_lines or [None] * len(user_config.rules)
    check_rules(user_config.rules, user_lines, source)
    loaded: list[LoadedRule] = []
    packs: dict[str, Any] = {}
    cap = config.settings.payment_cap_usd
    pack_budget: BudgetConfig | None = None

    def add(r: Rule, origin: str, line: int | None) -> None:
        loaded.append(
            LoadedRule(
                r,
                origin,
                line,
                CompiledMatch(
                    r.match,
                    project_root,
                    home,
                    settings_cap=cap,
                    delete_allow=config.settings.delete_allowlist,
                ),
            )
        )

    # order: self_protect, then user rules, then the other packs
    sp, sp_lines = load_pack(ALWAYS_FIRST)
    packs[ALWAYS_FIRST] = sp.model_dump(mode="json")
    for r, ln in zip(sp.rules, sp_lines, strict=True):
        add(r, ALWAYS_FIRST, ln)
    for r, ln in zip(user_config.rules, user_lines, strict=True):
        add(r, "user", ln)
    if shared is not None:
        srules = [r.model_copy(update={"id": f"shared.{r.id}"}) for r in shared.rules]
        slines = shared_lines or [None] * len(srules)
        check_rules(srules, slines, SHARED_REL, shadow=False)
        for r, ln in zip(srules, slines, strict=True):
            add(r, "shared", ln)
    for n in names[1:]:
        pk, lines = load_pack(n)
        packs[n] = pk.model_dump(mode="json")
        if pk.budget is not None:
            pack_budget = (
                pk.budget
                if pack_budget is None
                else BudgetConfig(
                    max_steps=min(pk.budget.max_steps, pack_budget.max_steps),
                    max_cost_usd=min(pk.budget.max_cost_usd, pack_budget.max_cost_usd),
                    max_repeats=min(pk.budget.max_repeats, pack_budget.max_repeats),
                )
            )
        for r, ln in zip(pk.rules, lines, strict=True):
            add(r, n, ln)
    ids: dict[str, str] = {}
    for lr in loaded:
        if lr.rule.id in ids:
            raise RulesError(
                f"duplicate rule id {lr.rule.id!r} (also in {ids[lr.rule.id]})", source, lr.line
            )
        ids[lr.rule.id] = lr.origin
    budget = config.budget
    if "budget" not in config.model_fields_set and pack_budget is not None:
        budget = pack_budget
        notes.append("budget taken from rule packs (lower personal defaults)")
    h = sha256_hex(
        canonical_json(
            {
                "config": config.model_dump(mode="json"),
                "packs": packs,
                "shared": shared.model_dump(mode="json") if shared is not None else None,
            }
        )
    )
    return Policy(config, loaded, h, project_root, home, source, budget, notes)


def shared_state(project_root: Path) -> tuple[str, str | None]:
    """('absent'|'unapproved'|'approved', sha256 of the shared file)."""
    f = project_root / SHARED_REL
    if not f.is_file():
        return "absent", None
    h = sha256_hex(f.read_bytes())
    ap = project_root / APPROVED_REL
    try:
        approved = ap.read_text().strip() if ap.is_file() else ""
    except OSError:
        approved = ""
    return ("approved" if approved == h else "unapproved"), h


def parse_shared(path: Path) -> tuple[SharedConfig, list[int | None]]:
    """Parse and schema-check a shared config; raises RulesError with file and line."""
    text = path.read_text("utf-8")
    data, node = parse_yaml(text, SHARED_REL)
    cfg: SharedConfig = _validate(SharedConfig, data, node, SHARED_REL)
    lines: list[int | None] = [None] * len(cfg.rules)
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            if k.value == "rules" and isinstance(v, yaml.SequenceNode):
                lines = [_line_of(n) for n in v.value]
    return cfg, lines


def validate_shared(shared: SharedConfig, base: Config, lines: list[int | None]) -> None:
    """Reject anything in a shared config that would loosen the user's own configuration."""
    if shared.mode is not None and MODE_RANK[shared.mode] < MODE_RANK[base.mode]:
        raise RulesError(
            f"shared config tries to loosen mode ({base.mode} -> {shared.mode}); it can only tighten",
            SHARED_REL,
        )
    for p in shared.packs:
        if p not in BUILTIN_PACKS:
            raise RulesError(f"unknown pack {p!r}", SHARED_REL)
    if shared.budget is not None:
        for fld in ("max_steps", "max_cost_usd", "max_repeats"):
            if getattr(shared.budget, fld) > getattr(base.budget, fld):
                raise RulesError(
                    f"shared config tries to raise budget.{fld} above the user's "
                    f"{getattr(base.budget, fld)}; it can only lower it",
                    SHARED_REL,
                )
    for r, ln in zip(shared.rules, lines, strict=True):
        if r.action == "allow":
            raise RulesError(
                f"shared rule {r.id!r} has action allow; a shared config may only add ask or deny "
                "rules (it can only tighten)",
                SHARED_REL,
                ln,
            )
        if len(r.id) > 56:
            raise RulesError(f"shared rule id {r.id!r} is too long", SHARED_REL, ln)


def merge_shared(base: Config, shared: SharedConfig) -> Config:
    """Merge under the user's config: stricter mode, union of packs, lower budget."""
    mode = base.mode
    if shared.mode is not None and MODE_RANK[shared.mode] > MODE_RANK[mode]:
        mode = shared.mode
    packs = list(base.packs) + [p for p in shared.packs if p not in base.packs]
    upd: dict[str, Any] = {"mode": mode, "packs": packs}
    if shared.budget is not None:
        upd["budget"] = BudgetConfig(
            max_steps=min(base.budget.max_steps, shared.budget.max_steps),
            max_cost_usd=min(base.budget.max_cost_usd, shared.budget.max_cost_usd),
            max_repeats=min(base.budget.max_repeats, shared.budget.max_repeats),
        )
    return base.model_copy(update=upd)


def approve_shared(project_root: Path) -> str:
    """Record the human's approval of the current shared.yaml hash. Returns the hash."""
    f = project_root / SHARED_REL
    if not f.is_file():
        raise RulesError("no shared config to approve", SHARED_REL)
    cfg, lines = parse_shared(f)
    validate_shared(cfg, load_user_config(project_root), lines)  # never approve a loosening file
    h = sha256_hex(f.read_bytes())
    ap = project_root / APPROVED_REL
    ap.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(ap.parent, 0o700)
    fd = os.open(ap, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, h.encode())
    finally:
        os.close(fd)
    return h


def load_user_config(project_root: Path) -> Config:
    """The user's own config (without shared), or the defaults."""
    p = project_root / CONFIG_FILE
    if not p.exists():
        return Config(version=1)
    data, node = parse_yaml(p.read_text("utf-8"), str(p))
    cfg: Config = _validate(Config, data, node, str(p))
    return cfg


def load_policy(
    path: Path | None,
    *,
    project_root: Path | None = None,
    home: str | None = None,
    use_shared: bool = True,
) -> Policy:
    """Load ``path`` (or built-in defaults when None). Raises RulesError on any problem.

    A committed ``.sheepdogai/shared.yaml`` is untrusted: it applies only when its sha256 matches
    the hash the user approved, and it can only tighten the user's own configuration.
    """
    root = project_root or (path.parent if path else Path.cwd())
    notes: list[str] = []
    shared: SharedConfig | None = None
    shared_lines: list[int | None] | None = None
    if path is None:
        cfg = Config(version=1)
        user_lines: list[int | None] = []
        source = "<default>"
    else:
        try:
            text = path.read_text("utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise RulesError(f"cannot read rules file: {e}", file=str(path)) from e
        data, node = parse_yaml(text, str(path))
        cfg = _validate(Config, data, node, str(path))
        user_lines = [None] * len(cfg.rules)
        if isinstance(node, yaml.MappingNode):
            for k, v in node.value:
                if k.value == "rules" and isinstance(v, yaml.SequenceNode):
                    user_lines = [_line_of(n) for n in v.value]
        source = str(path)
    if use_shared:
        state, h = shared_state(root)
        if state == "approved":
            shared, shared_lines = parse_shared(root / SHARED_REL)
            validate_shared(shared, cfg, shared_lines)
        elif state == "unapproved":
            notes.append(
                f"shared config {SHARED_REL} ignored: sha256 {str(h)[:12]} is not approved "
                f"(review it, then run: {CLI_NAME} approve-shared)"
            )
    pol = build_policy(
        cfg,
        project_root=str(root),
        home=home,
        source=source,
        user_lines=user_lines or None,
        shared=shared,
        shared_lines=shared_lines,
    )
    pol.notes.extend(notes)
    if shared is not None:
        pol.notes.append("shared config applied (can only tighten)")
    return pol
