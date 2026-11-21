"""sheepdogai: a safety and observability gate at the tool-call boundary of AI agents."""

from collections.abc import Callable
from typing import Any

from sheepdogai.constants import CLI_NAME, PACKAGE_NAME, __version__


def wrap(tool: Callable[..., Any], **kwargs: Any) -> Callable[..., Any]:
    """Guard a Python callable (experimental); see ``sheepdogai.adapters.wrap.wrap``."""
    from sheepdogai.adapters.wrap import wrap as _wrap

    return _wrap(tool, **kwargs)


__all__ = ["CLI_NAME", "PACKAGE_NAME", "__version__", "wrap"]
