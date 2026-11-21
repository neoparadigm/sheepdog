"""Error types. Every one of them is handled fail-closed by the callers."""

from __future__ import annotations


class SheepdogError(Exception):
    """Base class for all sheepdogai errors."""


class RulesError(SheepdogError):
    """A rules file is invalid. Startup must stop; the message names file and line."""

    def __init__(self, message: str, file: str = "<rules>", line: int | None = None) -> None:
        self.file = file
        self.line = line
        loc = f"{file}:{line}" if line is not None else file
        super().__init__(f"{loc}: {message}")


class ParseError(SheepdogError):
    """An adapter could not turn a raw payload into a ToolCallEvent."""


class LogError(SheepdogError):
    """The log could not be written or is corrupt."""
