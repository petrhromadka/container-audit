"""Map raw `docker inspect` JSON to Container models (read-only, no I/O)."""

from __future__ import annotations

from typing import Any

from ca.models import Container, Mount, PortBinding


def _as_dict(x: Any) -> dict:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> list:
    return x if isinstance(x, list) else []


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _str_items(x: Any) -> tuple[str, ...]:
    return tuple(i for i in _as_list(x) if isinstance(i, str))


def _parse_ports(ports: Any) -> tuple[PortBinding, ...]:
    """Flatten NetworkSettings.Ports; a null value means the port is not published."""
    result: list[PortBinding] = []
    for container_port, bindings in _as_dict(ports).items():
        for binding in _as_list(bindings):
            if not isinstance(binding, dict):
                continue
            result.append(
                PortBinding(
                    host_ip=_as_str(binding.get("HostIp")),
                    host_port=_as_str(binding.get("HostPort")),
                    container_port=_as_str(container_port),
                )
            )
    return tuple(result)


def _parse_mounts(mounts: Any) -> tuple[Mount, ...]:
    result: list[Mount] = []
    for item in _as_list(mounts):
        if not isinstance(item, dict):
            continue
        result.append(
            Mount(
                source=_as_str(item.get("Source")) or _as_str(item.get("Name")),
                destination=_as_str(item.get("Destination")),
                mode=_as_str(item.get("Mode")),
                rw=bool(item.get("RW", True)),
                mount_type=_as_str(item.get("Type")),
            )
        )
    return tuple(result)


def _parse_one(obj: dict[str, Any]) -> Container:
    config = _as_dict(obj.get("Config"))
    host_config = _as_dict(obj.get("HostConfig"))
    state = _as_dict(obj.get("State"))
    network = _as_dict(obj.get("NetworkSettings"))
    restart = _as_dict(host_config.get("RestartPolicy"))

    return Container(
        id=_as_str(obj.get("Id")),
        name=_as_str(obj.get("Name")).lstrip("/"),
        image=_as_str(config.get("Image")),
        image_id=_as_str(obj.get("Image")),
        status=_as_str(state.get("Status")),
        user=_as_str(config.get("User")),
        privileged=host_config.get("Privileged") is True,
        cap_add=_str_items(host_config.get("CapAdd")),
        cap_drop=_str_items(host_config.get("CapDrop")),
        pid_mode=_as_str(host_config.get("PidMode")),
        network_mode=_as_str(host_config.get("NetworkMode")),
        readonly_rootfs=host_config.get("ReadonlyRootfs") is True,
        ports=_parse_ports(network.get("Ports")),
        mounts=_parse_mounts(obj.get("Mounts")),
        env=_str_items(config.get("Env")),
        restart_policy=_as_str(restart.get("Name")),
        raw=obj,
    )


def parse_inspect(objects: list[dict]) -> list[Container]:
    """Parse `docker inspect` JSON objects into Container models; non-dict items are skipped."""
    return [_parse_one(o) for o in objects if isinstance(o, dict)]
