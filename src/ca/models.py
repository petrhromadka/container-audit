"""Shared data types. Every module imports from here; keep it dependency-free.

The whole tool is read-only: it parses `docker inspect` output and reports
misconfigurations. It never starts, stops, or changes a container.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered so findings sort high-to-low with `sorted(..., reverse=True)`."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class PortBinding:
    """A published port. `host_ip` empty means Docker's default (all interfaces)."""

    host_ip: str
    host_port: str
    container_port: str  # e.g. "5432/tcp"

    @property
    def all_interfaces(self) -> bool:
        return self.host_ip in ("", "0.0.0.0", "::")  # noqa: S104 - detecting this, not binding


@dataclass(frozen=True)
class Mount:
    source: str  # host path (bind) or volume name
    destination: str  # path inside the container
    mode: str  # "rw" / "ro" as reported
    rw: bool
    mount_type: str  # "bind", "volume", "tmpfs", ...


@dataclass(frozen=True)
class Container:
    """The essentials parsed from one `docker inspect` object, plus the raw dict."""

    id: str
    name: str
    image: str
    image_id: str
    status: str  # running, exited, ...
    user: str  # Config.User; "" or "0"/"root" means root
    privileged: bool
    cap_add: tuple[str, ...]
    cap_drop: tuple[str, ...]
    pid_mode: str
    network_mode: str
    readonly_rootfs: bool
    ports: tuple[PortBinding, ...]
    mounts: tuple[Mount, ...]
    env: tuple[str, ...] = field(repr=False)  # raw "KEY=VALUE"; repr hidden so secrets never leak
    restart_policy: str
    image_created: str = ""  # image build time from `docker image inspect`; "" if unknown
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def runs_as_root(self) -> bool:
        return self.user.strip() in ("", "0", "root", "0:0")


@dataclass(frozen=True)
class Finding:
    """One problem on one container. `evidence` must already be redacted."""

    check_id: str  # stable kebab-case id, e.g. "root-user"
    title: str
    severity: Severity
    container: str  # container name the finding is about
    detail: str  # human-readable explanation, safe to print publicly
    evidence: str = ""  # short redacted proof, e.g. "0.0.0.0:5432->5432/tcp"
    remediation: str = ""  # one-line fix suggestion


# A check receives every collected container and yields findings. Pure, read-only.
CheckFn = Callable[[list[Container]], Iterable[Finding]]


@dataclass
class Report:
    host: str
    scanned: int  # number of containers inspected
    findings: list[Finding]
    timestamp: str  # ISO 8601 UTC

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)
