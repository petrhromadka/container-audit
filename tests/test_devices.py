from __future__ import annotations

from typing import Any

from ca.checks import devices, get_checks
from ca.models import Container, Severity


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
        raw={} if raw is None else raw,
    )


def ids(check: Any, containers: list[Container]) -> list[tuple[str, Severity, str]]:
    return [(f.check_id, f.severity, f.container) for f in check(containers)]


def test_host_devices() -> None:
    bad = make(
        name="bad",
        raw={"HostConfig": {"Devices": [{"PathOnHost": "/dev/sda"}, {"PathOnHost": "/dev/sdb"}]}},
    )
    found = list(devices.host_devices([bad]))
    assert [(f.check_id, f.severity, f.container) for f in found] == [
        ("host-devices", Severity.MEDIUM, "bad")
    ]
    assert "/dev/sda" in found[0].evidence
    assert "2 entries" in found[0].evidence
    assert ids(devices.host_devices, [make(raw={"HostConfig": {"Devices": []}})]) == []
    assert ids(devices.host_devices, [make()]) == []


def test_shared_network_container() -> None:
    bad = make(name="bad", network_mode="container:db")
    found = list(devices.shared_network_container([bad]))
    assert [(f.check_id, f.severity, f.container) for f in found] == [
        ("shared-network-container", Severity.MEDIUM, "bad")
    ]
    assert "container:db" in found[0].evidence
    assert ids(devices.shared_network_container, [make(network_mode="bridge")]) == []
    assert ids(devices.shared_network_container, [make(network_mode="host")]) == []


def test_dangerous_sysctls() -> None:
    bad = make(name="bad", raw={"HostConfig": {"Sysctls": {"Net.IPv4.Ip_Forward": "1"}}})
    found = list(devices.dangerous_sysctls([bad]))
    assert [(f.check_id, f.severity, f.container) for f in found] == [
        ("dangerous-sysctls", Severity.MEDIUM, "bad")
    ]
    assert "Net.IPv4.Ip_Forward" in found[0].evidence
    app_level = make(raw={"HostConfig": {"Sysctls": {"fs.mqueue.msg_max": "100"}}})
    assert ids(devices.dangerous_sysctls, [app_level]) == []
    assert ids(devices.dangerous_sysctls, [make(raw={"HostConfig": {"Sysctls": {}}})]) == []
    assert ids(devices.dangerous_sysctls, [make()]) == []


def test_oom_kill_disable() -> None:
    bad = make(name="bad", raw={"HostConfig": {"OomKillDisable": True}})
    assert ids(devices.oom_kill_disable, [bad]) == [("oom-kill-disable", Severity.LOW, "bad")]
    assert (
        ids(devices.oom_kill_disable, [make(raw={"HostConfig": {"OomKillDisable": False}})]) == []
    )
    assert ids(devices.oom_kill_disable, [make()]) == []


def test_missing_raw_does_not_crash() -> None:
    bare = make(raw={})
    found = [f for check in devices.CHECKS for f in check([bare])]
    assert found == []


def test_registered_in_get_checks() -> None:
    checks = get_checks()
    assert all(check in checks for check in devices.CHECKS)
    bad = make(
        name="bad",
        network_mode="container:db",
        raw={
            "HostConfig": {
                "Devices": [{"PathOnHost": "/dev/sda"}],
                "Sysctls": {"kernel.msgmax": "1"},
                "OomKillDisable": True,
            }
        },
    )
    found = {f.check_id for check in checks for f in check([bad])}
    assert {
        "host-devices",
        "shared-network-container",
        "dangerous-sysctls",
        "oom-kill-disable",
    } <= found
