"""CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

from ca.checks import get_checks
from ca.models import Container, Finding, Report, Severity
from ca.report import render

_FAIL_LEVELS = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="container-audit", description="Read-only security audit of a Docker host."
    )
    p.add_argument("--input", metavar="PATH", help="JSON array of `docker inspect` objects")
    p.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    p.add_argument("--include-stopped", action="store_true", help="also audit stopped containers")
    p.add_argument(
        "--fail-on",
        choices=["none", *_FAIL_LEVELS],
        default="none",
        help="exit 1 if any finding is at or above this severity",
    )
    return p


def _load(args: argparse.Namespace) -> list[Container] | None:
    if args.input:
        from ca.collect import parse_inspect

        objects = json.loads(Path(args.input).read_text(encoding="utf-8"))
        return parse_inspect(objects)

    from ca.docker_cli import collect_running, docker_available

    if not docker_available():
        print("error: docker is not available (is it installed and running?)", file=sys.stderr)
        return None
    return collect_running(include_stopped=args.include_stopped)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    containers = _load(args)
    if containers is None:
        return 2

    findings: list[Finding] = []
    for check in get_checks():
        findings.extend(check(containers))

    report = Report(
        host=socket.gethostname(),
        scanned=len(containers),
        findings=findings,
        timestamp=datetime.now(UTC).isoformat(),
    )
    print(render(report, args.format))

    if args.fail_on != "none" and report.worst >= _FAIL_LEVELS[args.fail_on]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
