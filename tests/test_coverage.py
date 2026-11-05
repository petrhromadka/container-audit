"""End-to-end coverage for checks the main sample fixture does not trigger."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "sample_inspect_extra.json"
EXPECTED = {
    "host-pid",
    "host-network",
    "host-uts",
    "sensitive-host-mount",
    "unpinned-image",
    "secret-in-env",
}


def _run(capsys: pytest.CaptureFixture[str], fmt: str) -> str:
    assert main(["--input", str(FIXTURE), "--format", fmt]) == 0
    return capsys.readouterr().out


def _findings(capsys: pytest.CaptureFixture[str]) -> list[dict]:
    return json.loads(_run(capsys, "json"))["findings"]


def test_extra_fixture_triggers_remaining_checks(capsys: pytest.CaptureFixture[str]) -> None:
    ids = {f["check_id"] for f in _findings(capsys)}
    assert ids >= EXPECTED


def test_secret_in_env_flags_url_credential_and_bare_key(
    capsys: pytest.CaptureFixture[str],
) -> None:
    secrets = [f for f in _findings(capsys) if f["check_id"] == "secret-in-env"]
    assert len(secrets) == 2
    evidence = " ".join(f["evidence"] for f in secrets)
    assert "DATABASE_URL=" in evidence
    assert "KEY=" in evidence


@pytest.mark.parametrize("fmt", ["json", "text", "markdown"])
def test_raw_secret_values_never_appear_in_output(
    capsys: pytest.CaptureFixture[str], fmt: str
) -> None:
    out = _run(capsys, fmt)
    assert "s3cr3t" not in out
    assert "abcdef" not in out
