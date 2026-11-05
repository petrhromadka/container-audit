"""Render a Report as text / json / markdown."""

from __future__ import annotations

import json
import unicodedata

from ca.models import Finding, Report, Severity


def _sanitize(text: str) -> str:
    """Drop control (Cc), format (Cf) and other C* characters so output cannot drive a terminal."""
    return "".join(ch for ch in text if not unicodedata.category(ch).startswith("C"))


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, f.container, f.check_id))


def _as_dict(f: Finding) -> dict[str, str]:
    return {
        "check_id": _sanitize(f.check_id),
        "title": _sanitize(f.title),
        "severity": f.severity.label,
        "container": _sanitize(f.container),
        "detail": _sanitize(f.detail),
        "evidence": _sanitize(f.evidence),
        "remediation": _sanitize(f.remediation),
    }


def _text(report: Report) -> str:
    lines = [
        "container-audit report",
        f"Host:      {_sanitize(report.host)}",
        f"Scanned:   {report.scanned} container(s)",
        f"Timestamp: {_sanitize(report.timestamp)}",
    ]
    counts = ", ".join(
        f"{sev.label}={sum(1 for f in report.findings if f.severity == sev)}"
        for sev in sorted(Severity, reverse=True)
    )
    lines.append(f"Findings:  {len(report.findings)} ({counts})")
    lines.append("")
    if not report.findings:
        lines.append("No findings.")
    for f in _sorted(report.findings):
        d = _as_dict(f)
        lines.append(f"[{f.severity.name}] {d['check_id']}  {d['container']} - {d['detail']}")
        if d["evidence"]:
            lines.append(f"    evidence:    {d['evidence']}")
        if d["remediation"]:
            lines.append(f"    remediation: {d['remediation']}")
    return "\n".join(lines) + "\n"


def _json(report: Report) -> str:
    data = {
        "host": _sanitize(report.host),
        "scanned": report.scanned,
        "timestamp": _sanitize(report.timestamp),
        "worst": report.worst.label,
        "findings": [_as_dict(f) for f in _sorted(report.findings)],
    }
    return json.dumps(data, indent=2, sort_keys=False)


def _cell(text: str) -> str:
    out = _sanitize(text.replace("\n", " ").replace("\r", " "))
    out = out.replace("\\", "\\\\")  # a lone backslash before "|" would otherwise cancel its escape
    for ch in "|`<>[":
        out = out.replace(ch, "\\" + ch)
    return out


def _markdown(report: Report) -> str:
    host = _sanitize(report.host).replace("`", "'")  # inside a code span, escapes do not work
    lines = [
        "# container-audit report",
        "",
        f"Host `{host}`, {report.scanned} container(s) "
        f"scanned at {_cell(report.timestamp)}: "
        f"{len(report.findings)} finding(s), worst severity {report.worst.label}.",
        "",
    ]
    if not report.findings:
        lines.append("No findings.")
    else:
        lines.append("| Severity | Check | Container | Detail | Remediation |")
        lines.append("| --- | --- | --- | --- | --- |")
        for f in _sorted(report.findings):
            cells = [f.severity.label, f.check_id, f.container, f.detail, f.remediation]
            lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    return "\n".join(lines) + "\n"


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _sarif(report: Report) -> str:
    findings = _sorted(report.findings)
    rules = []
    seen: set[str] = set()
    for f in findings:
        check_id = _sanitize(f.check_id)
        if check_id in seen:
            continue
        seen.add(check_id)
        rules.append(
            {
                "id": check_id,
                "name": check_id,
                "shortDescription": {"text": _sanitize(f.title)},
                "defaultConfiguration": {"level": _sarif_level(f.severity)},
            }
        )
    results = [
        {
            "ruleId": _sanitize(f.check_id),
            "level": _sarif_level(f.severity),
            "message": {"text": _sanitize(f.detail)},
            "properties": {
                "container": _sanitize(f.container),
                "evidence": _sanitize(f.evidence),
                "remediation": _sanitize(f.remediation),
            },
        }
        for f in findings
    ]
    data = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "container-audit",
                        "informationUri": "https://github.com/petrhromadka/container-audit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(data, indent=2, sort_keys=False)


_RENDERERS = {"text": _text, "json": _json, "markdown": _markdown, "sarif": _sarif}


def render(report: Report, fmt: str = "text") -> str:
    try:
        renderer = _RENDERERS[fmt]
    except KeyError:
        raise ValueError(f"unknown format: {fmt!r}") from None
    return renderer(report)
