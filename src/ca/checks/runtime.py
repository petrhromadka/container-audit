"""Runtime hardening checks: seccomp/apparmor profiles, capability dropping, healthchecks."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ca.models import CheckFn, Container, Finding, Severity


def _security_opt(c: Container) -> list[Any]:
    host_config = c.raw.get("HostConfig")
    if not isinstance(host_config, dict):
        return []
    opts = host_config.get("SecurityOpt")
    return list(opts) if isinstance(opts, list) else []


def _has_unconfined(c: Container, key: str) -> bool:
    target = f"{key}:unconfined"
    return any(str(opt).strip().lower().replace("=", ":") == target for opt in _security_opt(c))


def _normalize_cap(cap: str) -> str:
    return cap.strip().upper().removeprefix("CAP_")


def _healthcheck_test(c: Container) -> list[Any] | None:
    config = c.raw.get("Config")
    if not isinstance(config, dict):
        return None
    healthcheck = config.get("Healthcheck")
    if not isinstance(healthcheck, dict):
        return None
    test = healthcheck.get("Test")
    return list(test) if isinstance(test, list) else []


def seccomp_unconfined(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if _has_unconfined(c, "seccomp"):
            yield Finding(
                check_id="seccomp-unconfined",
                title="Seccomp profile disabled (unconfined)",
                severity=Severity.HIGH,
                container=c.name,
                detail="The default seccomp syscall filter is disabled, widening the kernel "
                "attack surface.",
                evidence="HostConfig.SecurityOpt contains seccomp=unconfined",
                remediation="Remove `seccomp=unconfined`; use the default profile.",
            )


def apparmor_unconfined(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if _has_unconfined(c, "apparmor"):
            yield Finding(
                check_id="apparmor-unconfined",
                title="AppArmor profile disabled (unconfined)",
                severity=Severity.MEDIUM,
                container=c.name,
                detail="The container runs without an AppArmor profile, removing a layer of "
                "mandatory access control.",
                evidence="HostConfig.SecurityOpt contains apparmor=unconfined",
                remediation="Use the default `docker-default` AppArmor profile.",
            )


def caps_not_dropped(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if "ALL" not in {_normalize_cap(cap) for cap in c.cap_drop}:
            yield Finding(
                check_id="caps-not-dropped",
                title="Default capabilities are not dropped",
                severity=Severity.LOW,
                container=c.name,
                detail="The container keeps Docker's default capability set instead of dropping "
                "all and adding only what's needed.",
                evidence="cap_drop does not contain ALL",
                remediation="`cap_drop: [ALL]` then add back only required caps.",
            )


def no_healthcheck(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        test = _healthcheck_test(c)
        if not test or test == ["NONE"]:
            yield Finding(
                check_id="no-healthcheck",
                title="Container has no healthcheck",
                severity=Severity.LOW,
                container=c.name,
                detail="No container healthcheck, so orchestration can't detect an unhealthy "
                "container.",
                evidence="Config.Healthcheck is missing or disabled",
                remediation="Add a HEALTHCHECK to the image or compose.",
            )


CHECKS: list[CheckFn] = [
    seccomp_unconfined,
    apparmor_unconfined,
    caps_not_dropped,
    no_healthcheck,
]
