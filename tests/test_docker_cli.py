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


def test_collect_running_attaches_image_build_time(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    outputs = {
        "ps": "c1\n",
        "container": json.dumps([{"Id": "c1", "Name": "/app", "Image": "sha256:img"}]),
        "image": json.dumps([{"Id": "sha256:img", "Created": "2024-01-02T00:00:00Z", "RootFS": 1}]),
    }

    def fake_run(args: list[str], allow_failure: bool = False) -> str:
        calls.append(args)
        return outputs["ps" if args[0] == "ps" else args[2]]

    monkeypatch.setattr(docker_cli, "_run", fake_run)
    [container] = docker_cli.collect_running()

    assert container.name == "app"
    assert container.image_created == "2024-01-02T00:00:00Z"
    assert calls[-1] == ["inspect", "--type", "image", "--", "sha256:img"]


def test_image_inspect_skips_deleted_images(monkeypatch: pytest.MonkeyPatch) -> None:
    """A running container whose image was deleted must not abort the audit."""
    _patch_which(monkeypatch, DOCKER)
    found = json.dumps([{"Id": "sha256:ok", "Created": "2024-01-02T00:00:00Z", "RootFS": 1}])
    monkeypatch.setattr(
        subprocess, "run", lambda *_a, **_k: _Proc(1, found, "No such image: sha256:gone")
    )

    result = docker_cli.inspect_json(["sha256:ok", "sha256:gone"], "image", best_effort=True)

    assert [o["Id"] for o in result] == ["sha256:ok"]
    with pytest.raises(RuntimeError, match="No such image"):
        docker_cli.inspect_json(["sha256:ok", "sha256:gone"], "image")
