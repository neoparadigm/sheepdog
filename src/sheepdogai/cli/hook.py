"""``sheepdogai hook <cli>``: read the payload on stdin, ask the daemon, print the response."""

from __future__ import annotations

import sys


def run_hook(cli: str, experimental: bool) -> int:
    """Return the process exit code after writing the response. Never raises."""
    try:
        payload = sys.stdin.buffer.read(21 * 1024 * 1024)
    except BaseException as e:
        sys.stderr.write(f"sheepdogai: cannot read payload ({type(e).__name__}) (fail closed)\n")
        return 2
    from sheepdogai.daemon.client import request

    code, out, err = request(cli, payload, experimental=experimental)
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()
    if err:
        sys.stderr.write(err if err.endswith("\n") else err + "\n")
    return code
