"""TOML config file: discovery, merge precedence, and clean error handling."""

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


def _write_input(tmp_path: Path) -> str:
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


def _config(tmp_path: Path, body: str) -> str:
    path = tmp_path / "container-audit.toml"
    path.write_text(body, encoding="utf-8")
    return str(path)


def test_config_ignore_honored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], two_checks: None
) -> None:
    cfg = _config(tmp_path, 'ignore = ["writable-rootfs"]\n')
    inp = _write_input(tmp_path)
    assert main(["--input", inp, "--format", "json", "--config", cfg]) == 0
    assert _ids(capsys.readouterr().out) == {"root-user"}


def test_cli_ignore_unions_with_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], two_checks: None
) -> None:
    cfg = _config(tmp_path, 'ignore = ["writable-rootfs"]\n')
    inp = _write_input(tmp_path)
    assert main(["--input", inp, "--format", "json", "--config", cfg, "--ignore", "root-user"]) == 0
    assert _ids(capsys.readouterr().out) == set()


def test_config_min_severity_and_fail_on_apply(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], two_checks: None
) -> None:
    cfg = _config(tmp_path, 'min_severity = "high"\nfail_on = "high"\n')
    inp = _write_input(tmp_path)
    assert main(["--input", inp, "--format", "json", "--config", cfg]) == 1
    assert _ids(capsys.readouterr().out) == {"writable-rootfs"}


def test_cli_flag_overrides_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], two_checks: None
) -> None:
    cfg = _config(tmp_path, 'min_severity = "high"\nfail_on = "high"\n')
    inp = _write_input(tmp_path)
    exit_code = main(
        ["--input", inp, "--format", "json", "--config", cfg, "--min-severity", "info"]
    )
    assert exit_code == 1
    assert _ids(capsys.readouterr().out) == {"writable-rootfs", "root-user"}


def test_missing_config_file_returns_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], two_checks: None
) -> None:
    inp = _write_input(tmp_path)
    missing = str(tmp_path / "missing.toml")
    assert main(["--input", inp, "--config", missing]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert "Traceback" not in err


def test_malformed_config_returns_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], two_checks: None
) -> None:
    cfg = _config(tmp_path, "this is = = not toml\n")
    inp = _write_input(tmp_path)
    assert main(["--input", inp, "--config", cfg]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert "Traceback" not in err


def test_unknown_key_returns_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], two_checks: None
) -> None:
    cfg = _config(tmp_path, 'bogus = "x"\n')
    inp = _write_input(tmp_path)
    assert main(["--input", inp, "--config", cfg]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert "Traceback" not in err


def test_no_config_behavior_unchanged(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    two_checks: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)  # tmp_path holds no config file
    inp = _write_input(tmp_path)
    assert main(["--input", inp, "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["scanned"] == 1
    assert {f["check_id"] for f in data["findings"]} == {"writable-rootfs", "root-user"}
