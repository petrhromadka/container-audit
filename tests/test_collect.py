from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca.collect import parse_inspect
from ca.models import Mount, PortBinding

INSPECT = {
    "Id": "abc123",
    "Name": "/db",
    "Image": "sha256:deadbeef",
    "State": {"Status": "running"},
    "Config": {
        "Image": "postgres:16",
        "User": "",
        "Env": ["DB_PASSWORD=hunter2"],
    },
    "HostConfig": {
        "Privileged": True,
        "CapAdd": ["SYS_ADMIN"],
        "CapDrop": None,
        "PidMode": "host",
        "NetworkMode": "bridge",
        "ReadonlyRootfs": False,
        "RestartPolicy": {"Name": "always"},
    },
    "Mounts": [
        {
            "Type": "bind",
            "Source": "/var/run/docker.sock",
            "Destination": "/var/run/docker.sock",
            "Mode": "rw",
            "RW": True,
        }
    ],
    "NetworkSettings": {
        "Ports": {
            "5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}],  # noqa: S104 - fixture data
            "6379/tcp": None,
        }
    },
}


def test_parse_inspect_maps_every_field() -> None:
    (c,) = parse_inspect([INSPECT])

    assert c.id == "abc123"
    assert c.name == "db"
    assert c.image == "postgres:16"
    assert c.image_id == "sha256:deadbeef"
    assert c.status == "running"
    assert c.user == ""
    assert c.runs_as_root
    assert c.privileged is True
    assert c.cap_add == ("SYS_ADMIN",)
    assert c.cap_drop == ()
    assert c.pid_mode == "host"
    assert c.network_mode == "bridge"
    assert c.readonly_rootfs is False
    assert c.env == ("DB_PASSWORD=hunter2",)
    assert c.restart_policy == "always"
    assert c.mounts == (Mount("/var/run/docker.sock", "/var/run/docker.sock", "rw", True, "bind"),)
    assert c.ports == (PortBinding("0.0.0.0", "5432", "5432/tcp"),)  # noqa: S104 - fixture data
    assert c.ports[0].all_interfaces
    assert c.raw is INSPECT


def test_parse_inspect_empty_object_does_not_crash() -> None:
    (c,) = parse_inspect([{}])

    assert c.id == ""
    assert c.ports == ()
    assert c.mounts == ()
    assert c.env == ()
    assert c.runs_as_root


def test_sample_fixture_good_and_bad() -> None:
    path = Path(__file__).parent / "fixtures" / "sample_inspect.json"
    bad, good = parse_inspect(json.loads(path.read_text(encoding="utf-8")))

    assert bad.runs_as_root and bad.privileged
    assert bad.ports[0].all_interfaces
    assert "DB_PASSWORD=hunter2" in bad.env
    assert any(m.source == "/var/run/docker.sock" for m in bad.mounts)

    assert not good.runs_as_root and good.readonly_rootfs
    assert [(p.host_ip, p.host_port) for p in good.ports] == [("127.0.0.1", "8080")]
    assert not good.ports[0].all_interfaces


def test_parse_inspect_skips_non_dict_items() -> None:
    assert parse_inspect([1, "x", None, [], {}]) == parse_inspect([{}])
    assert len(parse_inspect([1, {}])) == 1
    assert parse_inspect([1]) == []


@pytest.mark.parametrize(
    "hostile",
    [
        {"Config": 5},
        {"HostConfig": "x"},
        {"HostConfig": {"RestartPolicy": 5}},
        {"State": []},
        {"NetworkSettings": 5},
        {"Name": 5},
        {"Id": 5, "Image": 5},
        {"Config": {"User": 5, "Image": []}},
        {"State": {"Status": 5}},
        {"HostConfig": {"PidMode": 5, "NetworkMode": {}, "RestartPolicy": {"Name": 5}}},
        {"HostConfig": {"CapAdd": 5, "CapDrop": "ALL"}},
        {"Config": {"Env": "A=b"}},
        {"Mounts": 5},
        {"Mounts": {"a": 1}},
        {"NetworkSettings": {"Ports": 5}},
        {"NetworkSettings": {"Ports": {"80/tcp": 5}}},
    ],
)
def test_parse_inspect_wrong_types_fall_back_to_defaults(hostile: dict) -> None:
    (c,) = parse_inspect([hostile])

    assert c.raw is hostile
    assert c.cap_add == () and c.cap_drop == ()
    assert c.env == () and c.mounts == () and c.ports == ()
    assert c.name == "" and c.id == "" and c.user == "" and c.restart_policy == ""
    assert c.pid_mode == "" and c.network_mode == "" and c.status == ""


def test_parse_inspect_keeps_only_string_list_items() -> None:
    (c,) = parse_inspect(
        [
            {
                "Config": {"Env": [1, "A=b", None]},
                "HostConfig": {"CapAdd": [1, "NET_ADMIN"], "CapDrop": [["x"], "ALL"]},
            }
        ]
    )

    assert c.env == ("A=b",)
    assert c.cap_add == ("NET_ADMIN",)
    assert c.cap_drop == ("ALL",)


def test_parse_inspect_bad_mounts_and_ports_keep_valid_entries() -> None:
    (c,) = parse_inspect(
        [
            {
                "Mounts": [1, {"Source": 5, "Name": "vol", "Destination": [], "Mode": 1}],
                "NetworkSettings": {
                    "Ports": {
                        "5432/tcp": [1, {"HostIp": 5, "HostPort": 80}, {"HostIp": "127.0.0.1"}],
                    }
                },
            }
        ]
    )

    assert c.mounts == (Mount("vol", "", "", True, ""),)
    assert c.ports == (
        PortBinding("", "", "5432/tcp"),  # wrong-typed HostIp/HostPort -> defaults
        PortBinding("127.0.0.1", "", "5432/tcp"),
    )
