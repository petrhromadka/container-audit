import json

from ca.models import Finding, Report, Severity
from ca.report import render


def _finding(sev: Severity, check_id: str, container: str, **kw: str) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"{check_id} title",
        severity=sev,
        container=container,
        detail=kw.get("detail", "something is wrong"),
        evidence=kw.get("evidence", "ev"),
        remediation=kw.get("remediation", "fix it"),
    )


def _report() -> Report:
    return Report(
        host="h1",
        scanned=3,
        findings=[
            _finding(Severity.CRITICAL, "docker-sock", "db"),
            _finding(Severity.MEDIUM, "stale-image", "web"),
            _finding(Severity.LOW, "root-user", "web"),
            _finding(Severity.LOW, "root-user", "cache"),
        ],
        timestamp="2026-01-01T00:00:00+00:00",
    )


def test_sarif_structure() -> None:
    report = _report()
    data = json.loads(render(report, "sarif"))
    assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "container-audit"
    assert len(run["results"]) == len(report.findings)
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert sorted(rule_ids) == ["docker-sock", "root-user", "stale-image"]


def test_sarif_level_mapping() -> None:
    data = json.loads(render(_report(), "sarif"))
    results = data["runs"][0]["results"]
    by_rule = {r["ruleId"]: r["level"] for r in results}
    assert by_rule["docker-sock"] == "error"
    assert by_rule["stale-image"] == "warning"
    assert by_rule["root-user"] == "note"


def test_sarif_sanitizes_ansi() -> None:
    hostile = "\x1b[31mred\x1b[0m"
    f = Finding(
        check_id=hostile,
        title=hostile,
        severity=Severity.HIGH,
        container=hostile,
        detail=hostile,
        evidence=hostile,
        remediation=hostile,
    )
    out = render(Report(host="h", scanned=1, findings=[f], timestamp="t"), "sarif")
    assert "\x1b" not in out
    json.loads(out)


def test_sarif_empty() -> None:
    data = json.loads(render(Report(host="h", scanned=0, findings=[], timestamp="t"), "sarif"))
    assert data["runs"][0]["results"] == []
    assert data["runs"][0]["tool"]["driver"]["rules"] == []
