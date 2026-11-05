"""Thin read-only wrapper around the Docker CLI: only `docker ps` and `docker inspect`."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from ca.collect import parse_inspect
from ca.models import Container

_INSPECT_CHUNK = 100


def _docker_path() -> str | None:
    return shutil.which("docker")


def docker_available() -> bool:
    return _docker_path() is not None


def _run(args: list[str]) -> str:
    path = _docker_path()
    if path is None:
        raise RuntimeError("docker executable not found in PATH")
    try:
        proc = subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("docker timed out after 30s") from exc
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
    result: list[dict[str, Any]] = []
    for start in range(0, len(ids), _INSPECT_CHUNK):
        chunk = ids[start : start + _INSPECT_CHUNK]
        out = _run(["inspect", "--type", "container", "--", *chunk])
        try:
            data = json.loads(out)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"docker inspect returned invalid JSON: {exc}") from exc
        result.extend(data)
    return result


def collect_running(include_stopped: bool = False) -> list[Container]:
    """List containers with `docker ps -q` (`-a` if requested) and parse their inspect data."""
    args = ["ps", "-q"]
    if include_stopped:
        args.append("-a")
    ids = _run(args).split()
    return parse_inspect(inspect_json(ids))
