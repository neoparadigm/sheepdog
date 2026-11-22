"""The ``/sheepdogai`` chat command for Claude Code (a skill) and Gemini CLI (a custom command).

Formats verified 2026-11-21: Claude skills are ``~/.claude/skills/<name>/SKILL.md`` with YAML
frontmatter (https://code.claude.com/docs/en/skills); Gemini custom commands are
``~/.gemini/commands/<name>.toml`` with ``description`` and ``prompt`` (``{{args}}``)
(https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/custom-commands.md).
"""

from __future__ import annotations

import contextlib
from pathlib import Path

from sheepdogai.constants import CLI_NAME

BODY = f"""You are helping the user check and tune **{CLI_NAME}**, the safety guard that screens every tool
call this agent makes. Speak plainly: assume the user is not technical. Do the thing, then say what
happened in one or two short sentences.

What the user asked: $ARGUMENTS

Pick the matching action. Run commands with your shell tool.

- **Is it working? / status / health** -> run `{CLI_NAME} doctor` and summarise: all good, or which line
  failed and the exact fix command shown on it.
- **What did it block? / what happened?** -> run `{CLI_NAME} recent -n 20` and summarise in plain words:
  how many blocked, asked, allowed; list the blocked ones with the reason.
- **Why was X blocked?** -> run `{CLI_NAME} recent -n 50`, find X, explain the reason in plain words, and
  say what a safe alternative would be.
- **Make it stricter / looser** -> run `{CLI_NAME} mode strict|balanced|relaxed`. strict = asks about
  anything no rule matched; balanced (the default) = the safety rules decide and everything else is left to
  the agent's own permissions; relaxed = balanced with fewer questions from the safety packs. Tell the user they will be asked to approve this change: that is intended.
- **Stop asking me about <command>** -> confirm the exact command pattern with the user, then run
  `{CLI_NAME} allow '<pattern>'` (for example `git status*`). Warn once that allow rules run before the
  safety packs. Never allow broad patterns like `*`.
- **Always block <command>** -> `{CLI_NAME} block '<pattern>'`.
- **Nothing specific** -> run `{CLI_NAME} doctor`, then `{CLI_NAME} recent -n 10`, and summarise both.

Rules for you:
- Never edit {CLI_NAME} config files, the hook settings or the `.sheepdogai` folder yourself; use the commands
  above only. Never run `{CLI_NAME} setup`, `install`, `uninstall`, `approve-shared` or `init`.
- If {CLI_NAME} blocks something you were doing, do not look for a workaround. Tell the user what was
  blocked and why, and let them decide.
- If a command says `{CLI_NAME}` is not found, tell the user to run `uv tool install sheepdogai` and then
  `{CLI_NAME} setup`.
"""

ALIASES = (CLI_NAME, "sheepdog")  # /sheepdogai and the short /sheepdog


def claude_skill(name: str) -> str:
    """SKILL.md text for the slash command ``/<name>``."""
    return f"""---
name: {name}
description: Check, explain and tune the {CLI_NAME} safety guard that screens this agent's tool calls. Use when the user asks whether {CLI_NAME} is working, what was blocked and why, or wants it stricter, looser, or to allow or block a specific command.
argument-hint: "[what you want, for example: what was blocked?]"
---

{BODY}"""


def gemini_command() -> str:
    """TOML text for a Gemini CLI custom command."""
    return (
        f'description = "Check, explain and tune the {CLI_NAME} safety guard"\n'
        'prompt = """\n' + BODY.replace("$ARGUMENTS", "{{args}}").replace('"""', "'''") + '"""\n'
    )


CLAUDE_SKILL = claude_skill(CLI_NAME)
GEMINI_COMMAND = gemini_command()


def skill_targets(home: Path) -> dict[str, list[tuple[Path, str]]]:
    """cli -> [(file, content)] for each chat command name we install."""
    return {
        "claude": [
            (home / ".claude" / "skills" / n / "SKILL.md", claude_skill(n)) for n in ALIASES
        ],
        "gemini": [
            (home / ".gemini" / "commands" / f"{n}.toml", gemini_command()) for n in ALIASES
        ],
    }


def install_skill(cli: str, home: Path) -> list[Path]:
    """Write the chat commands (never overwrites a different file the user made)."""
    done: list[Path] = []
    for path, content in skill_targets(home).get(cli, []):
        if path.exists() and path.read_text() != content:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        done.append(path)
    return done


def remove_skill(cli: str, home: Path) -> bool:
    """Remove our chat commands if unchanged. True if any was removed."""
    removed = False
    for path, content in skill_targets(home).get(cli, []):
        if path.exists() and path.read_text() == content:
            path.unlink()
            removed = True
            with contextlib.suppress(OSError):
                path.parent.rmdir()
    return removed
