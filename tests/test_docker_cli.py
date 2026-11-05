from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from ca import docker_cli

DOCKER = "/abs/path/docker"


class _Proc:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_which(monkeypatch: pytest.MonkeyPatch, value: str | None) -> None:
    monkeypatch.setattr(docker_cli.shutil, "which", lambda _name: value)


def test_docker_available(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_which(monkeypatch, None)
    assert docker_cli.docker_available() is False
    _patch_which(monkeypatch, DOCKER)
    assert docker_cli.docker_available() is True


def test_run_raises_when_docker_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_which(monkeypatch, None)
    with pytest.raises(RuntimeError, match="docker executable not found in PATH"):
        docker_cli._run(["ps"])


def test_run_nonzero_exit_includes_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_which(monkeypatch, DOCKER)
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_k: _Proc(returncode=1, stderr="  boom  "))
    with pytest.raises(RuntimeError, match=r"exit 1.*boom"):
        docker_cli._run(["ps"])


def test_inspect_json_chunks_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_which(monkeypatch, DOCKER)
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: Any) -> _Proc:
        calls.append(argv)
        n = len(argv) - argv.index("--") - 1
        return _Proc(stdout=json.dumps([{"Id": i} for i in argv[-n:]]))

    monkeypatch.setattr(subprocess, "run", fake_run)
    ids = [f"id{i}" for i in range(250)]

    result = docker_cli.inspect_json(ids)

    assert len(calls) == 3
    assert [len(c) - c.index("--") - 1 for c in calls] == [100, 100, 50]
    assert all(c[0] == DOCKER and c[1] == "inspect" for c in calls)
    assert [o["Id"] for o in result] == ids


def test_inspect_json_empty_makes_no_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_a: Any, **_k: Any) -> _Proc:
        raise AssertionError("subprocess.run must not be called")

    monkeypatch.setattr(subprocess, "run", fail)
    assert docker_cli.inspect_json([]) == []
