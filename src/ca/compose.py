"""Audit a docker-compose.yml without a running daemon.

Each compose service is translated into a `docker inspect`-shaped dict and then fed to
`ca.collect.parse_inspect`, so every existing (and future) check works unchanged. The
mapping is best-effort: compose is a build-time description, not a daemon's view, so some
runtime-only fields are approximated and bad input is coerced or skipped rather than fatal.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ca.collect import parse_inspect
from ca.models import Container

_MEMORY_SUFFIXES = {"b": 1, "k": 1024, "m": 1024**2, "g": 1024**3}


def _as_dict(x: Any) -> dict:
    return x if isinstance(x, dict) else {}


def _as_list(x: Any) -> list:
    if isinstance(x, list):
        return x
    return [x] if isinstance(x, str) else []


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _str_list(x: Any) -> list[str] | None:
    """A list of strings, or None if the value is absent/unusable (so callers can omit it)."""
    if not isinstance(x, list):
        return None
    return [i for i in x if isinstance(i, str)]


def _env(value: Any) -> list[str]:
    """Normalize `environment` (list of "K=V" or mapping {K: V}) to ["K=V", ...]."""
    if isinstance(value, dict):
        out = []
        for k, v in value.items():
            key = str(k)
            out.append(key if v is None else f"{key}={v}")
        return out
    if isinstance(value, list):
        return [i for i in value if isinstance(i, str)]
    return []


def _parse_memory(value: Any) -> int:
    """Convert a compose memory limit (int bytes or "512m"/"1g"/"536870912") to bytes."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value if value > 0 else 0
    if not isinstance(value, str):
        return 0
    text = value.strip().lower()
    if not text:
        return 0
    suffix = text[-1]
    if suffix in _MEMORY_SUFFIXES:
        number, unit = text[:-1], _MEMORY_SUFFIXES[suffix]
    else:
        number, unit = text, 1
    try:
        return int(float(number) * unit)
    except ValueError:
        return 0


def _service_memory(service: dict[str, Any]) -> int:
    if "mem_limit" in service:
        mem = _parse_memory(service.get("mem_limit"))
        if mem:
            return mem
    limits = _as_dict(_as_dict(_as_dict(service.get("deploy")).get("resources")).get("limits"))
    return _parse_memory(limits.get("memory"))


def _healthcheck(service: dict[str, Any]) -> dict[str, Any] | None:
    """Config.Healthcheck for a service, or None to omit (so no-healthcheck fires)."""
    hc = service.get("healthcheck")
    if not isinstance(hc, dict):
        return None
    if hc.get("disable") is True:
        return {"Test": ["NONE"]}
    test = hc.get("test")
    if isinstance(test, list):
        return {"Test": [str(i) for i in test]}
    if isinstance(test, str):
        return {"Test": ["CMD-SHELL", test]}
    return None


def _port_entry(host_ip: str, published: str, target: str, proto: str) -> tuple[str, Any]:
    key = f"{target}/{proto}"
    if not published:
        return key, None
    return key, [{"HostIp": host_ip, "HostPort": published}]


def _parse_port(spec: Any) -> tuple[str, Any] | None:
    """One compose port (short string or long mapping) -> a NetworkSettings.Ports item."""
    if isinstance(spec, int):
        spec = str(spec)
    if isinstance(spec, str):
        text, _, proto = spec.partition("/")
        proto = proto or "tcp"
        parts = text.split(":")
        if len(parts) == 1:
            return _port_entry("", "", parts[0], proto)
        if len(parts) == 2:
            return _port_entry("", parts[0], parts[1], proto)
        return _port_entry(parts[0], parts[1], parts[2], proto)
    if isinstance(spec, dict):
        target = spec.get("target")
        if target is None:
            return None
        proto = _as_str(spec.get("protocol")) or "tcp"
        published = spec.get("published")
        return _port_entry(
            _as_str(spec.get("host_ip")),
            "" if published is None else str(published),
            str(target),
            proto,
        )
    return None


def _parse_ports(value: Any) -> dict[str, Any]:
    ports: dict[str, Any] = {}
    for spec in _as_list(value):
        entry = _parse_port(spec)
        if entry is not None:
            ports[entry[0]] = entry[1]
    return ports


def _looks_like_path(source: str) -> bool:
    return source.startswith(("/", ".", "~"))


def _parse_mount(spec: Any) -> dict[str, Any] | None:
    """One compose volume (short "src:dst[:mode]" or long mapping) -> a Mounts item."""
    if isinstance(spec, str):
        parts = spec.split(":")
        if len(parts) == 1:
            source, destination, mode = "", parts[0], "rw"
        elif len(parts) == 2:
            source, destination, mode = parts[0], parts[1], "rw"
        else:
            source, destination, mode = parts[0], parts[1], parts[2]
        mount_type = "bind" if _looks_like_path(source) else "volume"
        return {
            "Type": mount_type,
            "Source": source,
            "Destination": destination,
            "RW": "ro" not in mode.split(","),
            "Mode": mode,
        }
    if isinstance(spec, dict):
        source = _as_str(spec.get("source"))
        mount_type = _as_str(spec.get("type")) or ("bind" if _looks_like_path(source) else "volume")
        read_only = spec.get("read_only") is True
        return {
            "Type": mount_type,
            "Source": source,
            "Destination": _as_str(spec.get("target")),
            "RW": not read_only,
            "Mode": "ro" if read_only else "rw",
        }
    return None


def _parse_mounts(value: Any) -> list[dict[str, Any]]:
    mounts = []
    for spec in _as_list(value):
        mount = _parse_mount(spec)
        if mount is not None:
            mounts.append(mount)
    return mounts


def _parse_devices(value: Any) -> list[dict[str, str]]:
    devices = []
    for spec in _as_list(value):
        if not isinstance(spec, str):
            continue
        parts = spec.split(":")
        host = parts[0]
        container = parts[1] if len(parts) > 1 else host
        devices.append({"PathOnHost": host, "PathInContainer": container})
    return devices


def _to_inspect(name: str, service: dict[str, Any]) -> dict[str, Any]:
    config: dict[str, Any] = {
        "Image": _as_str(service.get("image")),
        "User": _as_str(service.get("user")),
        "Env": _env(service.get("environment")),
    }
    healthcheck = _healthcheck(service)
    if healthcheck is not None:
        config["Healthcheck"] = healthcheck

    host_config: dict[str, Any] = {
        "Privileged": bool(service.get("privileged")),
        "ReadonlyRootfs": bool(service.get("read_only")),
        "SecurityOpt": _str_list(service.get("security_opt")) or [],
        "PidMode": _as_str(service.get("pid")),
        "NetworkMode": _as_str(service.get("network_mode")),
        "IpcMode": _as_str(service.get("ipc")),
        "UTSMode": _as_str(service.get("uts")),
    }
    cap_add = _str_list(service.get("cap_add"))
    if cap_add is not None:
        host_config["CapAdd"] = cap_add
    cap_drop = _str_list(service.get("cap_drop"))
    if cap_drop is not None:
        host_config["CapDrop"] = cap_drop
    memory = _service_memory(service)
    if memory:
        host_config["Memory"] = memory
    devices = _parse_devices(service.get("devices"))
    if devices:
        host_config["Devices"] = devices

    return {
        "Name": "/" + name,
        "Config": config,
        "HostConfig": host_config,
        "NetworkSettings": {"Ports": _parse_ports(service.get("ports"))},
        "Mounts": _parse_mounts(service.get("volumes")),
        "State": {"Status": "n/a"},
    }


def parse_compose(path: str | Path) -> list[Container]:
    """Parse a docker-compose.yml into Container models via the existing inspect pipeline."""
    try:
        import yaml  # optional extra, installed via the [compose] group in pyproject
    except ImportError as exc:
        raise RuntimeError(
            "compose support needs PyYAML: install docker-host-audit[compose]"
        ) from exc

    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    services = _as_dict(_as_dict(data).get("services"))
    objects = [
        _to_inspect(str(name), svc) for name, svc in services.items() if isinstance(svc, dict)
    ]
    return parse_inspect(objects)
