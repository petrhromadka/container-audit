import json
from pathlib import Path

import pytest

from ca import cli
from ca.models import Container, Finding, Report, Severity
from ca.report import render


def _finding(sev: Severity, check_id: str, container: str, detail: str = "bad") -> Finding:
    return Finding(
        check_id=check_id,
        title=check_id,
        severity=sev,
        container=container,
        detail=detail,
        evidence="ev",
        remediation="fix it",
    )


@pytest.fixture
def report() -> Report:
    return Report(
        host="h1",
        scanned=2,
        findings=[
            _finding(Severity.LOW, "root-user", "web"),
            _finding(Severity.CRITICAL, "docker-sock", "db", "a|b"),
        ],
        timestamp="2026-01-01T00:00:00+00:00",
    )


def test_text(report: Report) -> None:
    out = render(report)
    assert "db" in out
    assert "[CRITICAL]" in out
    assert "[LOW]" in out
    assert out.index("[CRITICAL]") < out.index("[LOW]")
    assert "fix it" in out


def test_text_no_findings() -> None:
    out = render(Report("h", 0, [], "t"))
    assert "No findings" in out


def test_json(report: Report) -> None:
    data = json.loads(render(report, "json"))
    assert list(data) == ["host", "scanned", "timestamp", "worst", "findings"]
    assert data["worst"] == "critical"
    assert len(data["findings"]) == 2
    assert data["findings"][0]["severity"] == "critical"
    assert set(data["findings"][0]) == {
        "check_id",
        "title",
        "severity",
        "container",
        "detail",
        "evidence",
        "remediation",
    }


def test_markdown(report: Report) -> None:
    out = render(report, "markdown")
    assert out.startswith("# container-audit report")
    assert "| Severity | Check | Container | Detail | Remediation |" in out
    assert r"a\|b" in out


def test_unknown_format(report: Report) -> None:
    with pytest.raises(ValueError, match="xml"):
        render(report, "xml")


def _container(name: str) -> Container:
    return Container(
        id="1",
        name=name,
        image="img",
        image_id="sha",
        status="running",
        user="",
        privileged=False,
        cap_add=(),
        cap_drop=(),
        pid_mode="",
        network_mode="bridge",
        readonly_rootfs=False,
        ports=(),
        mounts=(),
        env=(),
        restart_policy="no",
    )


@pytest.fixture
def cli_input(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    path = tmp_path / "inspect.json"
    path.write_text("[{}]", encoding="utf-8")
    monkeypatch.setattr("ca.collect.parse_inspect", lambda _objs: [_container("web")])
    monkeypatch.setattr(
        cli, "get_checks", lambda: [lambda cs: [_finding(Severity.HIGH, "x", cs[0].name)]]
    )
    return str(path)


@pytest.mark.parametrize(
    ("fail_on", "code"),
    [("none", 0), ("low", 1), ("high", 1), ("critical", 0)],
)
def test_cli_fail_on(cli_input: str, fail_on: str, code: int) -> None:
    assert cli.main(["--input", cli_input, "--fail-on", fail_on]) == code


def test_cli_format(cli_input: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--input", cli_input, "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["scanned"] == 1
    assert data["findings"][0]["container"] == "web"
