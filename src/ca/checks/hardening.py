"""Host-isolation hardening checks: shared namespaces, no-new-privileges, memory limits."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ca.models import CheckFn, Container, Finding, Severity


def _host_config(c: Container) -> dict[str, Any]:
    host_config = c.raw.get("HostConfig")
    return host_config if isinstance(host_config, dict) else {}


def host_network(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if c.network_mode == "host":
            yield Finding(
                check_id="host-network",
                title="Container shares the host network namespace",
                severity=Severity.HIGH,
                container=c.name,
                detail="The container shares the host network namespace, bypassing network "
                "isolation and port mapping.",
                evidence="HostConfig.NetworkMode=host",
                remediation="Use a bridge or user-defined network instead of `network_mode: host`.",
            )


def host_ipc(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if _host_config(c).get("IpcMode") == "host":
            yield Finding(
                check_id="host-ipc",
                title="Container shares the host IPC namespace",
                severity=Severity.MEDIUM,
                container=c.name,
                detail="The container can access host shared memory and IPC objects, "
                "weakening isolation.",
                evidence="HostConfig.IpcMode=host",
                remediation="Remove `ipc: host`; do not share the host IPC namespace.",
            )


def host_uts(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if _host_config(c).get("UTSMode") == "host":
            yield Finding(
                check_id="host-uts",
                title="Container shares the host UTS namespace",
                severity=Severity.LOW,
                container=c.name,
                detail="The container shares the host hostname and domain name namespace.",
                evidence="HostConfig.UTSMode=host",
                remediation="Remove `uts: host`; do not share the host UTS namespace.",
            )


def no_new_privileges_missing(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        security_opt = _host_config(c).get("SecurityOpt") or []
        enabled = any(
            str(opt).strip().lower().replace("=", ":") == "no-new-privileges:true"
            for opt in security_opt
        )
        if not enabled:
            yield Finding(
                check_id="no-new-privileges-missing",
                title="no-new-privileges is not set",
                severity=Severity.MEDIUM,
                container=c.name,
                detail="Without no-new-privileges, setuid binaries inside the container "
                "can escalate privileges.",
                evidence="HostConfig.SecurityOpt lacks no-new-privileges",
                remediation='Add `security_opt: ["no-new-privileges:true"]`.',
            )


def unlimited_memory(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if not _host_config(c).get("Memory"):
            yield Finding(
                check_id="unlimited-memory",
                title="Container has no memory limit",
                severity=Severity.LOW,
                container=c.name,
                detail="With no memory limit, one container can exhaust the host's RAM.",
                evidence="HostConfig.Memory=0",
                remediation="Set a memory limit (`mem_limit` in compose).",
            )


CHECKS: list[CheckFn] = [
    host_network,
    host_ipc,
    host_uts,
    no_new_privileges_missing,
    unlimited_memory,
]
