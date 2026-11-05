"""Thin read-only wrapper around the Docker CLI: only `docker ps` and `docker inspect`."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from ca.collect import parse_inspect
from ca.models import Container


def docker_available() -> bool:
    return shutil.which("docker") is not None


def _run(args: list[str]) -> str:
    if not docker_available():
        raise RuntimeError("docker executable not found in PATH")
    try:
        proc = subprocess.run(
            ["docker", *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"failed to run docker: {exc}") from exc
    if proc.returncode != 0:
        raise RuntimeError(
            f"docker {args[0]} failed (exit {proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


def inspect_json(ids: list[str]) -> list[dict[str, Any]]:
    """Run `docker inspect` on the given container ids and return the parsed JSON."""
    if not ids:
        return []
    out = _run(["inspect", *ids])
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"docker inspect returned invalid JSON: {exc}") from exc
    return data


def collect_running(include_stopped: bool = False) -> list[Container]:
    """List containers with `docker ps -q` (`-a` if requested) and parse their inspect data."""
    args = ["ps", "-q"]
    if include_stopped:
        args.append("-a")
    ids = _run(args).split()
    return parse_inspect(inspect_json(ids))
