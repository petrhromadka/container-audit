from __future__ import annotations

from dataclasses import replace

from ca.checks.privilege import (
    dangerous_caps,
    docker_socket_mount,
    host_pid,
    privileged,
    root_user,
    sensitive_host_mount,
    writable_rootfs,
)
from ca.models import Container, Mount, Severity

CLEAN = Container(
    id="abc123",
    name="clean",
    image="nginx:1.27",
    image_id="sha256:0",
    status="running",
    user="1000",
    privileged=False,
    cap_add=(),
    cap_drop=("ALL",),
    pid_mode="",
    network_mode="bridge",
    readonly_rootfs=True,
    ports=(),
    mounts=(),
    env=(),
    restart_policy="no",
)


def _bind(source: str, destination: str = "/data", *, rw: bool = True) -> Mount:
    return Mount(source, destination, "rw" if rw else "ro", rw, "bind")


def test_root_user() -> None:
    assert list(root_user([CLEAN])) == []
    (f,) = root_user([replace(CLEAN, user="")])
    assert (f.check_id, f.severity, f.container) == ("root-user", Severity.HIGH, "clean")


def test_privileged() -> None:
    assert list(privileged([CLEAN])) == []
    (f,) = privileged([replace(CLEAN, privileged=True)])
    assert (f.check_id, f.severity) == ("privileged", Severity.CRITICAL)


def test_dangerous_caps() -> None:
    assert list(dangerous_caps([replace(CLEAN, cap_add=("CHOWN",))])) == []
    (f,) = dangerous_caps([replace(CLEAN, cap_add=("cap_sys_admin", "NET_ADMIN", "CHOWN"))])
    assert (f.check_id, f.severity) == ("dangerous-caps", Severity.HIGH)
    assert "SYS_ADMIN" in f.evidence
    assert "NET_ADMIN" in f.evidence
    assert "CHOWN" not in f.evidence


def test_docker_socket_mount() -> None:
    assert list(docker_socket_mount([replace(CLEAN, mounts=(_bind("/srv/app"),))])) == []
    bad = replace(CLEAN, mounts=(_bind("/var/run/docker.sock", "/var/run/docker.sock", rw=False),))
    (f,) = docker_socket_mount([bad])
    assert (f.check_id, f.severity) == ("docker-socket-mount", Severity.CRITICAL)


def test_sensitive_host_mount() -> None:
    safe = replace(
        CLEAN,
        mounts=(_bind("/srv/app"), _bind("/etc", rw=False), _bind("/var/run/docker.sock")),
    )
    assert list(sensitive_host_mount([safe])) == []
    bad = replace(CLEAN, mounts=(_bind("/etc", "/host-etc"), _bind("/home/alice")))
    findings = list(sensitive_host_mount([bad]))
    assert len(findings) == 2
    assert findings[0].check_id == "sensitive-host-mount"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].evidence == "/etc -> /host-etc (rw)"


def test_writable_rootfs() -> None:
    assert list(writable_rootfs([CLEAN])) == []
    (f,) = writable_rootfs([replace(CLEAN, readonly_rootfs=False)])
    assert (f.check_id, f.severity) == ("writable-rootfs", Severity.LOW)


def test_host_pid() -> None:
    assert list(host_pid([CLEAN])) == []
    (f,) = host_pid([replace(CLEAN, pid_mode="host")])
    assert (f.check_id, f.severity) == ("host-pid", Severity.HIGH)
