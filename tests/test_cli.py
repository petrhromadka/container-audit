"""CLI behaviour: hostname redaction and clean error handling."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from ca.cli import main

_CONTAINER = {
    "Id": "abc123",
    "Name": "/web",
    "Image": "sha256:deadbeef",
    "Config": {"Image": "nginx:latest", "User": "1000"},
    "HostConfig": {},
    "State": {"Status": "running"},
}


def _write(tmp_path: Path, text: str) -> str:
    path = tmp_path / "in.json"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_hostname_redacted_by_default(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _write(tmp_path, json.dumps([_CONTAINER]))
    assert main(["--input", path]) == 0
    out = capsys.readouterr().out
    assert "(redacted)" in out
    assert socket.gethostname() not in out


def test_include_host_shows_real_hostname(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path, json.dumps([_CONTAINER]))
    assert main(["--input", path, "--include-host"]) == 0
    out = capsys.readouterr().out
    assert socket.gethostname() in out
    assert "(redacted)" not in out


@pytest.mark.parametrize("content", ["{not json", '{"a":1}', "[1, 2]", "[" * 100000])
def test_bad_input_returns_2_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    assert main(["--input", _write(tmp_path, content)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert "Traceback" not in err
    assert str(tmp_path) not in err


def test_missing_input_file_returns_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "nope.json"
    assert main(["--input", str(missing)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:")
    assert "Traceback" not in err
    assert str(tmp_path) not in err
