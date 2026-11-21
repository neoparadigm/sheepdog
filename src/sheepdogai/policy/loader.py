"""Load and validate sheepdog.yaml and rule packs. Any problem raises RulesError (fail closed)."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from sheepdogai.core.canonical import canonical_json, sha256_hex
from sheepdogai.core.errors import RulesError
from sheepdogai.policy.matchers import CompiledMatch, check_regex_safe
from sheepdogai.policy.schema import BudgetConfig, Config, Match, PackFile, Rule

BUILTIN_PACKS = ("self_protect", "machine", "secrets", "repo", "network", "injection", "personal")
ALWAYS_FIRST = "self_protect"


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
        data = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
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


def check_rules(rules: list[Rule], lines: list[int | None], file: str) -> None:
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
        for j in range(i):
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
) -> Policy:
    """Compile a validated config + packs into a Policy."""
    home = home or os.path.expanduser("~")
    project_root = os.path.realpath(project_root)
    names = list(dict.fromkeys(config.packs))
    notes: list[str] = []
    if ALWAYS_FIRST in names:
        names.remove(ALWAYS_FIRST)
    else:
        notes.append("self_protect was not listed in packs; it is always enabled")
    names.insert(0, ALWAYS_FIRST)
    user_lines = user_lines or [None] * len(config.rules)
    check_rules(config.rules, user_lines, source)
    loaded: list[LoadedRule] = []
    packs: dict[str, Any] = {}
    cap = config.settings.payment_cap_usd
    pack_budget: BudgetConfig | None = None

    def add(r: Rule, origin: str, line: int | None) -> None:
        loaded.append(
            LoadedRule(
                r, origin, line, CompiledMatch(r.match, project_root, home, settings_cap=cap)
            )
        )

    # order: self_protect, then user rules, then the other packs
    sp, sp_lines = load_pack(ALWAYS_FIRST)
    packs[ALWAYS_FIRST] = sp.model_dump(mode="json")
    for r, ln in zip(sp.rules, sp_lines, strict=True):
        add(r, ALWAYS_FIRST, ln)
    for r, ln in zip(config.rules, user_lines, strict=True):
        add(r, "user", ln)
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
    h = sha256_hex(canonical_json({"config": config.model_dump(mode="json"), "packs": packs}))
    return Policy(config, loaded, h, project_root, home, source, budget, notes)


def load_policy(
    path: Path | None, *, project_root: Path | None = None, home: str | None = None
) -> Policy:
    """Load ``path`` (or built-in defaults when None). Raises RulesError on any problem."""
    root = project_root or (path.parent if path else Path.cwd())
    if path is None:
        return build_policy(Config(version=1), project_root=str(root), home=home)
    try:
        text = path.read_text("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise RulesError(f"cannot read rules file: {e}", file=str(path)) from e
    data, node = parse_yaml(text, str(path))
    cfg: Config = _validate(Config, data, node, str(path))
    lines: list[int | None] = [None] * len(cfg.rules)
    if isinstance(node, yaml.MappingNode):
        for k, v in node.value:
            if k.value == "rules" and isinstance(v, yaml.SequenceNode):
                lines = [_line_of(n) for n in v.value]
    return build_policy(cfg, project_root=str(root), home=home, source=str(path), user_lines=lines)
