"""`--ignore` suppresses findings before the report is built and before --fail-on."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca.cli import main
from ca.models import Container, Finding, Severity

_CONTAINER = {
    "Id": "abc123",
    "Name": "/web",
    "Image": "sha256:deadbeef",
    "Config": {"Image": "nginx:latest", "User": "1000"},
    "HostConfig": {},
    "State": {"Status": "running"},
}


def _write(tmp_path: Path) -> str:
    path = tmp_path / "in.json"
    path.write_text(json.dumps([_CONTAINER]), encoding="utf-8")
    return str(path)


def _high(_: list[Container]) -> list[Finding]:
    return [Finding("writable-rootfs", "rootfs", Severity.HIGH, "web", "writable")]


def _low(_: list[Container]) -> list[Finding]:
    return [Finding("root-user", "root", Severity.LOW, "web", "runs as root")]


def _ids(out: str) -> set[str]:
    return {f["check_id"] for f in json.loads(out)["findings"]}


@pytest.fixture
def two_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ca.cli.get_checks", lambda: [_high, _low])


def test_ignore_removes_matching_finding(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], two_checks: None
) -> None:
    path = _write(tmp_path)
    assert main(["--input", path, "--format", "json", "--ignore", "writable-rootfs"]) == 0
    assert _ids(capsys.readouterr().out) == {"root-user"}


def test_two_ignores_remove_both(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], two_checks: None
) -> None:
    path = _write(tmp_path)
    exit_code = main(
        [
            "--input",
            path,
            "--format",
            "json",
            "--ignore",
            "writable-rootfs",
            "--ignore",
            "root-user",
        ]
    )
    assert exit_code == 0
    assert _ids(capsys.readouterr().out) == set()


def test_ignore_affects_fail_on(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], two_checks: None
) -> None:
    path = _write(tmp_path)
    assert main(["--input", path, "--format", "json", "--fail-on", "high"]) == 1
    capsys.readouterr()
    args = ["--input", path, "--format", "json", "--fail-on", "high"]
    assert main([*args, "--ignore", "writable-rootfs"]) == 0


def test_without_ignore_count_unchanged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], two_checks: None
) -> None:
    path = _write(tmp_path)
    assert main(["--input", path, "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["scanned"] == 1
    assert {f["check_id"] for f in data["findings"]} == {"writable-rootfs", "root-user"}
