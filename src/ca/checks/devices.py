"""Device and kernel-exposure checks: host devices, shared netns, sysctls, OOM kill."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ca.models import CheckFn, Container, Finding, Severity


def _host_config(c: Container) -> dict[str, Any]:
    host_config = c.raw.get("HostConfig")
    return host_config if isinstance(host_config, dict) else {}


def host_devices(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        devices = _host_config(c).get("Devices")
        if isinstance(devices, list) and devices:
            first = devices[0] if isinstance(devices[0], dict) else {}
            path = first.get("PathOnHost", "")
            yield Finding(
                check_id="host-devices",
                title="Host devices are exposed to the container",
                severity=Severity.MEDIUM,
                container=c.name,
                detail="Host devices are passed through to the container, giving it direct "
                "access to host hardware.",
                evidence=f"HostConfig.Devices has {len(devices)} entr"
                f"{'y' if len(devices) == 1 else 'ies'}, first PathOnHost={path}",
                remediation="Remove device passthrough unless the container truly needs it.",
            )


def shared_network_container(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if c.network_mode.startswith("container:"):
            yield Finding(
                check_id="shared-network-container",
                title="Container shares another container's network namespace",
                severity=Severity.MEDIUM,
                container=c.name,
                detail="The container shares another container's network namespace, so they can "
                "reach each other's loopback services and traffic.",
                evidence=f"HostConfig.NetworkMode={c.network_mode}",
                remediation="Use a dedicated bridge or user-defined network instead.",
            )


def dangerous_sysctls(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        sysctls = _host_config(c).get("Sysctls")
        if not isinstance(sysctls, dict) or not sysctls:
            continue
        matching = [key for key in sysctls if str(key).lower().startswith(("kernel.", "net."))]
        if matching:
            yield Finding(
                check_id="dangerous-sysctls",
                title="Container sets kernel or network sysctls",
                severity=Severity.MEDIUM,
                container=c.name,
                detail="The container overrides kernel or network sysctls, which can weaken "
                "host isolation.",
                evidence=f"HostConfig.Sysctls sets {', '.join(sorted(matching))}",
                remediation="Drop custom sysctls unless they are strictly required.",
            )


def oom_kill_disable(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if _host_config(c).get("OomKillDisable") is True:
            yield Finding(
                check_id="oom-kill-disable",
                title="OOM killer is disabled for the container",
                severity=Severity.LOW,
                container=c.name,
                detail="The OOM killer is disabled for this container, so it can hang the host "
                "under memory pressure instead of being killed.",
                evidence="HostConfig.OomKillDisable=true",
                remediation="Do not set oom_kill_disable.",
            )


CHECKS: list[CheckFn] = [
    host_devices,
    shared_network_container,
    dangerous_sysctls,
    oom_kill_disable,
]
