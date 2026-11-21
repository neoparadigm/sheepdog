"""``sheepdogai verify-log <run>``."""

from __future__ import annotations

from pathlib import Path

from sheepdogai.log.verify import verify_log


def resolve_run(run: str, project: Path) -> Path:
    """A run is a path or a run id under the project's default log directory."""
    p = Path(run)
    if p.exists():
        return p
    return project / ".sheepdogai" / "runs" / f"{run}.jsonl"


def cmd_verify(run: str, project: Path) -> int:
    """Print the verification result; 0 when the chain is intact, 1 otherwise."""
    path = resolve_run(run, project)
    r = verify_log(path)
    if r.ok:
        seal = (
            "sealed by head sidecar"
            if r.sealed
            else "no head sidecar: tail truncation not detectable"
        )
        print(f"OK {path}: {r.records} records, chain intact ({seal})")
        return 0
    where = f"first broken record: {r.broken_at}" if r.broken_at is not None else "unreadable"
    print(f"BROKEN {path}: {where}: {r.reason}")
    return 1
