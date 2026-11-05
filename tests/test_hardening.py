from __future__ import annotations

from typing import Any

from ca.checks import get_checks, hardening
from ca.models import Container, Severity

HARDENED_RAW: dict[str, Any] = {
    "HostConfig": {
        "IpcMode": "private",
        "UTSMode": "",
        "SecurityOpt": ["no-new-privileges:true"],
        "Memory": 536870912,
    }
}


def make(
    name: str = "app",
    network_mode: str = "bridge",
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
        cap_drop=(),
        pid_mode="",
        network_mode=network_mode,
        readonly_rootfs=True,
        ports=(),
        mounts=(),
        env=(),
        restart_policy="no",
        raw=HARDENED_RAW if raw is None else raw,
    )


def with_host_config(**overrides: Any) -> Container:
    return make(raw={"HostConfig": {**HARDENED_RAW["HostConfig"], **overrides}})


def ids(check: Any, containers: list[Container]) -> list[tuple[str, Severity, str]]:
    return [(f.check_id, f.severity, f.container) for f in check(containers)]


def test_host_network() -> None:
    assert ids(hardening.host_network, [make(name="bad", network_mode="host")]) == [
        ("host-network", Severity.HIGH, "bad")
    ]
    assert ids(hardening.host_network, [make()]) == []


def test_host_ipc() -> None:
    assert ids(hardening.host_ipc, [with_host_config(IpcMode="host")]) == [
        ("host-ipc", Severity.MEDIUM, "app")
    ]
    assert ids(hardening.host_ipc, [make()]) == []


def test_host_uts() -> None:
    assert ids(hardening.host_uts, [with_host_config(UTSMode="host")]) == [
        ("host-uts", Severity.LOW, "app")
    ]
    assert ids(hardening.host_uts, [make()]) == []


def test_no_new_privileges_missing() -> None:
    expected = [("no-new-privileges-missing", Severity.MEDIUM, "app")]
    assert (
        ids(hardening.no_new_privileges_missing, [with_host_config(SecurityOpt=None)]) == expected
    )
    assert (
        ids(
            hardening.no_new_privileges_missing, [with_host_config(SecurityOpt=["seccomp=default"])]
        )
        == expected
    )
    assert ids(hardening.no_new_privileges_missing, [make()]) == []


def test_unlimited_memory() -> None:
    expected = [("unlimited-memory", Severity.LOW, "app")]
    assert ids(hardening.unlimited_memory, [with_host_config(Memory=0)]) == expected
    assert ids(hardening.unlimited_memory, [make()]) == []


def test_missing_raw_does_not_crash() -> None:
    bare = make(raw={})
    found = {f.check_id for check in hardening.CHECKS for f in check([bare])}
    assert found == {"no-new-privileges-missing", "unlimited-memory"}


def test_registered_in_get_checks() -> None:
    checks = get_checks()
    assert all(check in checks for check in hardening.CHECKS)
    bad = make(network_mode="host", raw={})
    found = {f.check_id for check in checks for f in check([bad])}
    assert {"host-network", "no-new-privileges-missing", "unlimited-memory"} <= found
