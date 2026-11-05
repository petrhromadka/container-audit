"""End-to-end test: real collect -> checks -> report pipeline over the sample fixture."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "sample_inspect.json"
SECRET = "hunter2"  # the fixture's fake secret value


def _run(capsys: pytest.CaptureFixture[str], *args: str, path: Path = FIXTURE) -> tuple[int, str]:
    code = main(["--input", str(path), *args])
    return code, capsys.readouterr().out


def _findings(capsys: pytest.CaptureFixture[str]) -> list[dict]:
    _, out = _run(capsys, "--format", "json")
    return json.loads(out)["findings"]


def test_bad_container_has_expected_findings(capsys: pytest.CaptureFixture[str]) -> None:
    findings = _findings(capsys)
    bad_ids = {f["check_id"] for f in findings if f["container"] == "bad-db"}
    assert {
        "docker-socket-mount",
        "privileged",
        "root-user",
        "secret-in-env",
        "port-all-interfaces",
        "stale-image",
    } <= bad_ids


def test_good_container_has_no_findings(capsys: pytest.CaptureFixture[str]) -> None:
    assert [f for f in _findings(capsys) if f["container"] == "good-web"] == []


@pytest.mark.parametrize("fmt", ["text", "json", "markdown"])
def test_format_is_nonempty_and_never_leaks_secret(
    capsys: pytest.CaptureFixture[str], fmt: str
) -> None:
    code, out = _run(capsys, "--format", fmt)
    assert code == 0
    assert out.strip()
    assert SECRET not in out


def test_fail_on_none_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert _run(capsys, "--fail-on", "none")[0] == 0


@pytest.mark.parametrize("level", ["low", "medium", "high", "critical"])
def test_fail_on_level_reached_returns_one(capsys: pytest.CaptureFixture[str], level: str) -> None:
    # The fixture's worst finding is critical, so every level is reached.
    assert _run(capsys, "--fail-on", level)[0] == 1


def test_fail_on_returns_zero_when_no_findings(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    good_only = [c for c in json.loads(FIXTURE.read_text("utf-8")) if c.get("Name") == "/good-web"]
    path = tmp_path / "good.json"
    path.write_text(json.dumps(good_only), encoding="utf-8")
    assert _run(capsys, "--fail-on", "low", path=path)[0] == 0
