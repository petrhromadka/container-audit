"""Privilege and isolation checks: root users, privileged mode, risky mounts."""

from __future__ import annotations

from collections.abc import Iterable

from ca.models import CheckFn, Container, Finding, Mount, Severity

DANGEROUS_CAPS = frozenset(
    {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"}
)
SENSITIVE_SOURCES = frozenset({"/", "/etc", "/root", "/var/run", "/proc", "/sys"})


def _normalize_cap(cap: str) -> str:
    cap = cap.strip().upper()
    return cap.removeprefix("CAP_")


def _is_docker_sock(mount: Mount) -> bool:
    return mount.source.endswith("docker.sock")


def _is_sensitive_source(source: str) -> bool:
    return source in SENSITIVE_SOURCES or source == "/home" or source.startswith("/home/")


def privileged(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if c.privileged:
            yield Finding(
                check_id="privileged",
                title="Container runs in privileged mode",
                severity=Severity.CRITICAL,
                container=c.name,
                detail="Privileged mode grants all capabilities and host device access, "
                "so a compromise is effectively a host compromise.",
                evidence="HostConfig.Privileged=true",
                remediation="Remove `privileged: true`; add only the capabilities needed.",
            )


def docker_socket_mount(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        for m in c.mounts:
            if _is_docker_sock(m):
                yield Finding(
                    check_id="docker-socket-mount",
                    title="Docker socket mounted into container",
                    severity=Severity.CRITICAL,
                    container=c.name,
                    detail="Access to the Docker socket grants control of the Docker daemon, "
                    "and therefore of the host.",
                    evidence=f"{m.source} -> {m.destination} ({'rw' if m.rw else 'ro'})",
                    remediation="Remove the socket mount or use a restricted docker-socket-proxy.",
                )


def root_user(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if c.runs_as_root:
            yield Finding(
                check_id="root-user",
                title="Container runs as root",
                severity=Severity.HIGH,
                container=c.name,
                detail="The main process runs as UID 0, widening the impact of an escape.",
                evidence=f"Config.User={c.user!r}",
                remediation="Set a non-root USER in the image or `user:` in compose.",
            )


def dangerous_caps(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        matched = sorted({_normalize_cap(cap) for cap in c.cap_add} & DANGEROUS_CAPS)
        if matched:
            yield Finding(
                check_id="dangerous-caps",
                title="Container adds dangerous Linux capabilities",
                severity=Severity.HIGH,
                container=c.name,
                detail="These capabilities allow administrative or host-affecting operations "
                "and weaken container isolation.",
                evidence="cap_add: " + ", ".join(matched),
                remediation="Remove these from `cap_add`; grant only what is required.",
            )


def sensitive_host_mount(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        for m in c.mounts:
            if (
                m.mount_type == "bind"
                and m.rw
                and not _is_docker_sock(m)
                and _is_sensitive_source(m.source)
            ):
                yield Finding(
                    check_id="sensitive-host-mount",
                    title="Sensitive host path mounted read-write",
                    severity=Severity.HIGH,
                    container=c.name,
                    detail="A writable bind mount of a sensitive host directory lets the container "
                    "modify host configuration or data.",
                    evidence=f"{m.source} -> {m.destination} (rw)",
                    remediation="Mount a narrower path, and read-only (`:ro`) where possible.",
                )


def host_pid(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if c.pid_mode == "host":
            yield Finding(
                check_id="host-pid",
                title="Container shares the host PID namespace",
                severity=Severity.HIGH,
                container=c.name,
                detail="The container can see and signal host processes, undermining isolation.",
                evidence="HostConfig.PidMode=host",
                remediation="Remove `pid: host` from the container configuration.",
            )


def writable_rootfs(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if not c.readonly_rootfs:
            yield Finding(
                check_id="writable-rootfs",
                title="Root filesystem is writable",
                severity=Severity.LOW,
                container=c.name,
                detail="A writable root filesystem lets an attacker persist changes.",
                evidence="HostConfig.ReadonlyRootfs=false",
                remediation="Set `read_only: true` and use tmpfs or volumes for writable paths.",
            )


CHECKS: list[CheckFn] = [
    privileged,
    docker_socket_mount,
    root_user,
    dangerous_caps,
    sensitive_host_mount,
    host_pid,
    writable_rootfs,
]
