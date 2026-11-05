"""Auditing a docker-compose.yml via --compose and the parse_compose translation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca.cli import main
from ca.compose import parse_compose

_COMPOSE = """\
services:
  app:
    image: redis:latest
    privileged: true
    cap_add:
      - SYS_ADMIN
    security_opt:
      - seccomp=unconfined
    ports:
      - "0.0.0.0:5432:5432"
    environment:
      DB_PASSWORD: s3cr3t-value
  web:
    image: nginx:1.27
    user: "1000"
    read_only: true
    cap_drop:
      - ALL
    mem_limit: 256m
    security_opt:
      - no-new-privileges:true
    ports:
      - "127.0.0.1:8080:80"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
"""


def _write(tmp_path: Path) -> str:
    path = tmp_path / "docker-compose.yml"
    path.write_text(_COMPOSE, encoding="utf-8")
    return str(path)


def test_compose_findings_via_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--compose", _write(tmp_path), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)

    app_checks = {f["check_id"] for f in data["findings"] if f["container"] == "app"}
    expected = {"privileged", "secret-in-env", "port-all-interfaces", "seccomp-unconfined"}
    assert expected <= app_checks

    web_checks = {f["check_id"] for f in data["findings"] if f["container"] == "web"}
    assert web_checks == set()


def test_parse_compose_fields(tmp_path: Path) -> None:
    containers = {c.name: c for c in parse_compose(_write(tmp_path))}
    assert set(containers) == {"app", "web"}

    app = containers["app"]
    assert app.image == "redis:latest"
    assert app.privileged is True
    assert "SYS_ADMIN" in app.cap_add
    assert any(e.startswith("DB_PASSWORD=") for e in app.env)
    assert any(p.all_interfaces and p.host_port == "5432" for p in app.ports)

    web = containers["web"]
    assert web.user == "1000"
    assert web.readonly_rootfs is True
    assert "ALL" in web.cap_drop
    assert web.raw["HostConfig"]["Memory"] == 256 * 1024 * 1024
    assert any(p.host_ip == "127.0.0.1" and p.host_port == "8080" for p in web.ports)
