"""Map raw `docker inspect` JSON to Container models (read-only, no I/O)."""

from __future__ import annotations

from typing import Any

from ca.models import Container, Mount, PortBinding


def _parse_ports(ports: dict[str, Any] | None) -> tuple[PortBinding, ...]:
    """Flatten NetworkSettings.Ports; a null value means the port is not published."""
    result: list[PortBinding] = []
    for container_port, bindings in (ports or {}).items():
        for binding in bindings or []:
            result.append(
                PortBinding(
                    host_ip=binding.get("HostIp") or "",
                    host_port=str(binding.get("HostPort") or ""),
                    container_port=container_port,
                )
            )
    return tuple(result)


def _parse_mounts(mounts: list[dict[str, Any]] | None) -> tuple[Mount, ...]:
    return tuple(
        Mount(
            source=m.get("Source") or m.get("Name") or "",
            destination=m.get("Destination") or "",
            mode=m.get("Mode") or "",
            rw=bool(m.get("RW", True)),
            mount_type=m.get("Type") or "",
        )
        for m in mounts or []
    )


def _parse_one(obj: dict[str, Any]) -> Container:
    config = obj.get("Config") or {}
    host_config = obj.get("HostConfig") or {}
    state = obj.get("State") or {}
    network = obj.get("NetworkSettings") or {}
    restart = host_config.get("RestartPolicy") or {}

    return Container(
        id=obj.get("Id") or "",
        name=(obj.get("Name") or "").lstrip("/"),
        image=config.get("Image") or "",
        image_id=obj.get("Image") or "",
        status=state.get("Status") or "",
        user=config.get("User") or "",
        privileged=bool(host_config.get("Privileged", False)),
        cap_add=tuple(host_config.get("CapAdd") or ()),
        cap_drop=tuple(host_config.get("CapDrop") or ()),
        pid_mode=host_config.get("PidMode") or "",
        network_mode=host_config.get("NetworkMode") or "",
        readonly_rootfs=bool(host_config.get("ReadonlyRootfs", False)),
        ports=_parse_ports(network.get("Ports")),
        mounts=_parse_mounts(obj.get("Mounts")),
        env=tuple(config.get("Env") or ()),
        restart_policy=restart.get("Name") or "",
        raw=obj,
    )


def parse_inspect(objects: list[dict]) -> list[Container]:
    """Parse a list of `docker inspect` JSON objects into Container models."""
    return [_parse_one(obj) for obj in objects]
