"""CLI usability: --version, --min-severity, python -m ca."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import ca
from ca.cli import main
from ca.models import Container, Finding, Severity


def _check(containers: list[Container]) -> list[Finding]:
    return [
        Finding("low-thing", "Low", Severity.LOW, "web", "a low problem"),
        Finding("high-thing", "High", Severity.HIGH, "web", "a high problem"),
    ]


@pytest.fixture
def input_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr("ca.cli.get_checks", lambda: [_check])
    path = tmp_path / "inspect.json"
    path.write_text(json.dumps([]), encoding="utf-8")
    return str(path)


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"container-audit {ca.__version__}"


def test_default_shows_all_findings(input_file: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--input", input_file]) == 0
    out = capsys.readouterr().out
    assert "low-thing" in out
    assert "high-thing" in out


def test_min_severity_hides_lower(input_file: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--input", input_file, "--min-severity", "high"]) == 0
    out = capsys.readouterr().out
    assert "high-thing" in out
    assert "low-thing" not in out


def test_fail_on_uses_filtered_set(input_file: str) -> None:
    assert main(["--input", input_file, "--min-severity", "high", "--fail-on", "high"]) == 1
    assert main(["--input", input_file, "--min-severity", "critical", "--fail-on", "low"]) == 0


def test_python_m_ca_importable() -> None:
    import ca.__main__  # noqa: F401
