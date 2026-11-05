from __future__ import annotations

from typing import Any

from ca.checks import get_checks, runtime
from ca.models import Container, Severity

HARDENED_RAW: dict[str, Any] = {
    "HostConfig": {
        "SecurityOpt": ["no-new-privileges:true", "seccomp=default"],
    },
    "Config": {
        "Healthcheck": {"Test": ["CMD-SHELL", "curl -f http://localhost/ || exit 1"]},
    },
}


def make(
    name: str = "app",
    cap_drop: tuple[str, ...] = ("ALL",),
    raw: dict[str, Any] | None = None,
) -> Container:
    return Container(
        id="abc123",
        name=name,
        image="app:1.0",
        image_id="sha256:abc",
        status="running",
        user="1000",
        privileged=False,
        cap_add=(),
        cap_drop=cap_drop,
        pid_mode="",
        network_mode="bridge",
        readonly_rootfs=True,
        ports=(),
        mounts=(),
        env=(),
        restart_policy="no",
        raw=HARDENED_RAW if raw is None else raw,
    )


def ids(check: Any, containers: list[Container]) -> list[tuple[str, Severity, str]]:
    return [(f.check_id, f.severity, f.container) for f in check(containers)]


def test_seccomp_unconfined() -> None:
    offending = make(raw={"HostConfig": {"SecurityOpt": ["SECCOMP:unconfined"]}})
    assert ids(runtime.seccomp_unconfined, [offending]) == [
        ("seccomp-unconfined", Severity.HIGH, "app")
    ]
    assert ids(runtime.seccomp_unconfined, [make()]) == []


def test_apparmor_unconfined() -> None:
    offending = make(raw={"HostConfig": {"SecurityOpt": ["apparmor=unconfined"]}})
    assert ids(runtime.apparmor_unconfined, [offending]) == [
        ("apparmor-unconfined", Severity.MEDIUM, "app")
    ]
    assert ids(runtime.apparmor_unconfined, [make()]) == []


def test_caps_not_dropped() -> None:
    assert ids(runtime.caps_not_dropped, [make(cap_drop=("NET_RAW",))]) == [
        ("caps-not-dropped", Severity.LOW, "app")
    ]
    # ALL with CAP_ prefix and odd casing still counts as dropped.
    assert ids(runtime.caps_not_dropped, [make(cap_drop=("cap_all",))]) == []
    assert ids(runtime.caps_not_dropped, [make()]) == []


def test_no_healthcheck() -> None:
    expected = [("no-healthcheck", Severity.LOW, "app")]
    assert ids(runtime.no_healthcheck, [make(raw={})]) == expected
    assert ids(runtime.no_healthcheck, [make(raw={"Config": {"Healthcheck": {"Test": []}}})]) == (
        expected
    )
    assert (
        ids(runtime.no_healthcheck, [make(raw={"Config": {"Healthcheck": {"Test": ["NONE"]}}})])
        == expected
    )
    assert ids(runtime.no_healthcheck, [make()]) == []


def test_registered_in_get_checks() -> None:
    checks = get_checks()
    assert all(check in checks for check in runtime.CHECKS)
    bad = make(
        cap_drop=(),
        raw={"HostConfig": {"SecurityOpt": ["seccomp=unconfined", "apparmor=unconfined"]}},
    )
    found = {f.check_id for check in checks for f in check([bad])}
    assert {
        "seccomp-unconfined",
        "apparmor-unconfined",
        "caps-not-dropped",
        "no-healthcheck",
    } <= found
