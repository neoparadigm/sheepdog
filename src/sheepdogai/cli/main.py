"""The ``sheepdog`` command. Heavy imports are deferred so ``hook`` starts fast."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sheepdogai.constants import CLI_NAME, CONFIG_FILE, __version__

INIT_TEMPLATE = """\
# sheepdog.yaml: strict by default. Hooks are guardrails, not isolation (see docs/limitations.md).
version: 1
mode: strict            # strict: ask when no rule matches | balanced: allow read-only | relaxed: allow
fail: closed            # the only supported value
packs: [self_protect, machine, secrets, repo, network, injection]
budget: {max_steps: 200, max_cost_usd: 5, max_repeats: 3}
approvals: {ask_timeout_s: 60, remember: session}
log: {path: .sheepdog/runs, hash_chain: true, redact_secrets: true}
decider: {type: rules}  # a Decider can only make a verdict stricter, never looser

# Your rules run before packs, top to bottom, first match wins.
rules:
  - id: no-force-push
    match: {tool: Bash, command: "git push --force*"}
    action: deny
    reason: force-push rewrites shared history
"""


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=CLI_NAME, description="Safety gate for AI agent tool calls.")
    p.add_argument("--version", action="version", version=f"{CLI_NAME} {__version__}")
    p.add_argument("--project", default=None, help="project root (default: nearest sheepdog.yaml)")
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init", help="write a commented strict sheepdog.yaml")
    i.add_argument("--force", action="store_true")
    for name in ("install", "uninstall"):
        s = sub.add_parser(name, help=f"{name} the hook for an agent CLI")
        s.add_argument("cli", choices=["claude", "codex", "gemini"])
        g = s.add_mutually_exclusive_group()
        g.add_argument(
            "--project-scope",
            "--project-config",
            dest="scope",
            action="store_const",
            const="project",
        )
        g.add_argument("--user", dest="scope", action="store_const", const="user")
        s.add_argument("--dry-run", action="store_true")
        s.add_argument("--experimental", action="store_true")
    h = sub.add_parser("hook", help="hook entry point (reads the payload on stdin)")
    h.add_argument("cli", choices=["claude", "codex", "gemini"])
    h.add_argument("--experimental", action="store_true")
    sub.add_parser("status", help="show policy, daemon and installed hooks")
    v = sub.add_parser("verify-log", help="verify a run's hash chain")
    v.add_argument("run")
    g2 = sub.add_parser("graph", help="export a run graph")
    g2.add_argument("run")
    g2.add_argument("--format", choices=["mermaid", "json", "jsonld"], default="mermaid")
    g2.add_argument("--only-denied", action="store_true")
    r = sub.add_parser("replay", help="re-feed a run through the current policy")
    r.add_argument("run")
    r.add_argument("--html", metavar="FILE", help="write a static HTML report")
    c = sub.add_parser("conformance", help="run the adapter conformance checks")
    c.add_argument("adapter", choices=["claude", "codex", "gemini"])
    b = sub.add_parser("bench", help="run the injection gauntlet")
    b.add_argument("--out", default=None)
    b.add_argument("--corpus", default="v1")
    d = sub.add_parser("daemon", help="run the daemon in the foreground")
    d.add_argument("--idle", type=float, default=1800.0)
    return p


def _project(a: argparse.Namespace) -> Path:
    if a.project:
        return Path(a.project).resolve()
    from sheepdogai.daemon.client import find_project

    return Path(find_project())


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["hook"]:  # fast path: no argparse, no heavy imports
        cli = argv[1] if len(argv) > 1 else ""
        if cli not in {"claude", "codex", "gemini"}:
            sys.stderr.write("sheepdog: unknown hook target (fail closed)\n")
            return 2
        from sheepdogai.cli.hook import run_hook

        return run_hook(cli, "--experimental" in argv[2:])
    a = _parser().parse_args(argv)
    try:
        return _dispatch(a)
    except Exception as e:
        print(f"{CLI_NAME}: error: {e}", file=sys.stderr)
        return 1


def _dispatch(a: argparse.Namespace) -> int:  # noqa: C901
    project = _project(a)
    home = Path.home()
    if a.cmd == "init":
        path = project / CONFIG_FILE
        if path.exists() and not a.force:
            print(f"{path} exists; use --force to overwrite", file=sys.stderr)
            return 1
        import os

        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, INIT_TEMPLATE.encode())
        os.close(fd)
        from sheepdogai.policy.loader import load_policy

        load_policy(path)  # the template must itself be valid
        print(f"wrote {path} (strict mode)")
        return 0
    if a.cmd in {"install", "uninstall"}:
        from sheepdogai.cli import install as inst

        if a.cli == "codex" and not a.experimental:
            print(
                "codex support is experimental; pass --experimental",
                file=sys.stderr,
            )
            return 1
        scope = a.scope or "project"
        if a.cmd == "install":
            plan = inst.install(a.cli, scope, project, home, a.dry_run)
            if not plan.changed:
                print(f"already installed in {plan.path}; nothing to do")
            else:
                print(plan.diff, end="")
                print(("would write " if a.dry_run else "wrote ") + str(plan.path))
        else:
            print(inst.uninstall(a.cli, scope, project, home, a.dry_run))
        return 0
    if a.cmd == "status":
        from sheepdogai.cli.status import cmd_status

        return cmd_status(project, home)
    if a.cmd == "verify-log":
        from sheepdogai.cli.verify_log import cmd_verify

        return cmd_verify(a.run, project)
    if a.cmd == "graph":
        from sheepdogai.cli.graph import cmd_graph

        return int(cmd_graph(a.run, project, a.format, a.only_denied))
    if a.cmd == "replay":
        from sheepdogai.cli.replay import cmd_replay

        return cmd_replay(a.run, project, a.html)
    if a.cmd == "conformance":
        from sheepdogai.cli.conformance import cmd_conformance

        return cmd_conformance(a.adapter)
    if a.cmd == "bench":
        import importlib

        try:
            mod = importlib.import_module("bench.injection_gauntlet.run")
        except ImportError:
            print(
                "bench needs a source checkout of the repository (bench/ is not packaged)",
                file=sys.stderr,
            )
            return 1
        return int(mod.cmd_bench(a.corpus, a.out))
    if a.cmd == "daemon":
        from sheepdogai.daemon.server import serve

        return serve(project, None, a.idle)
    return 2


if __name__ == "__main__":
    sys.exit(main())
