"""Exposure checks: published ports, secrets in env, unpinned images."""

from __future__ import annotations

import re
from collections.abc import Iterable

from ca.models import CheckFn, Container, Finding, Severity
from ca.redact import mask

# Matches credentials embedded in a URL, e.g. postgres://user:pass@host/db.
_URL_CREDENTIAL = re.compile(r"://[^/@:\s]+:[^/@\s]+@")

_SECRET_MARKERS = (
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "AUTH",
)
_PLACEHOLDERS = ("changeme", "example")
_PLACEHOLDER_PREFIXES = ("${", "/run/secrets/")


def _is_secret_name(key: str) -> bool:
    upper = key.upper()
    return (
        upper == "KEY"
        or upper.endswith("_KEY")
        or any(marker in upper for marker in _SECRET_MARKERS)
    )


def _is_placeholder(value: str) -> bool:
    stripped = value.strip()
    return (
        not stripped
        or stripped.lower() in _PLACEHOLDERS
        or stripped.startswith(_PLACEHOLDER_PREFIXES)
    )


def _is_unpinned(image: str) -> bool:
    if not image or "@" in image:
        return False
    last_segment = image.rsplit("/", 1)[-1]  # a colon before the last "/" is a registry port
    _, sep, tag = last_segment.partition(":")
    return not sep or tag == "latest"


def secret_in_env(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        for entry in c.env:
            key, sep, value = entry.partition("=")
            if not sep or _is_placeholder(value):
                continue
            if not _is_secret_name(key) and not _URL_CREDENTIAL.search(value):
                continue
            yield Finding(
                check_id="secret-in-env",
                title="Secret stored in environment variable",
                severity=Severity.HIGH,
                container=c.name,
                detail=(
                    f"Environment variable {key} looks like a secret and has a literal "
                    "value; it is visible via docker inspect and to anyone who can read the "
                    "container configuration."
                ),
                evidence=f"{key}={mask(value)}",
                remediation="Use Docker secrets or an env file kept outside the image.",
            )


def port_all_interfaces(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        for p in c.ports:
            if not p.all_interfaces:
                continue
            yield Finding(
                check_id="port-all-interfaces",
                title="Port published on all interfaces",
                severity=Severity.MEDIUM,
                container=c.name,
                detail="The port is reachable from every network the host is attached to.",
                evidence=f"0.0.0.0:{p.host_port} -> {p.container_port}",
                remediation="Bind to 127.0.0.1 (e.g. 127.0.0.1:<port>:<port>) unless public.",
            )


def unpinned_image(containers: list[Container]) -> Iterable[Finding]:
    for c in containers:
        if not _is_unpinned(c.image):
            continue
        yield Finding(
            check_id="unpinned-image",
            title="Image is not pinned",
            severity=Severity.LOW,
            container=c.name,
            detail="The image has no digest and uses no tag or the mutable ':latest' tag.",
            evidence=c.image,
            remediation="Pin to a digest (@sha256:...) or an explicit version tag.",
        )


CHECKS: list[CheckFn] = []
CHECKS.append(secret_in_env)
CHECKS.append(port_all_interfaces)
CHECKS.append(unpinned_image)
