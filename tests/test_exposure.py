from __future__ import annotations

from ca.checks.exposure import port_all_interfaces, secret_in_env, unpinned_image
from ca.models import Container, PortBinding, Severity


def make(
    *,
    image: str = "nginx:1.27",
    env: tuple[str, ...] = (),
    ports: tuple[PortBinding, ...] = (),
) -> Container:
    return Container(
        id="abc123",
        name="web",
        image=image,
        image_id="sha256:0",
        status="running",
        user="1000",
        privileged=False,
        cap_add=(),
        cap_drop=(),
        pid_mode="",
        network_mode="bridge",
        readonly_rootfs=False,
        ports=ports,
        mounts=(),
        env=env,
        restart_policy="no",
    )


def test_port_all_interfaces_fires_for_wildcard_only() -> None:
    open_port = make(ports=(PortBinding("0.0.0.0", "8080", "80/tcp"),))  # noqa: S104
    local_port = make(ports=(PortBinding("127.0.0.1", "8080", "80/tcp"),))

    findings = list(port_all_interfaces([open_port]))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].evidence == "0.0.0.0:8080 -> 80/tcp"
    assert list(port_all_interfaces([local_port])) == []


def test_secret_in_env_masks_value() -> None:
    findings = list(secret_in_env([make(env=("DB_PASSWORD=hunter2",))]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.evidence == "DB_PASSWORD=hu***"
    for text in (
        finding.title,
        finding.detail,
        finding.evidence,
        finding.remediation,
        finding.container,
    ):
        assert "hunter2" not in text


def test_secret_in_env_skips_non_secrets_and_placeholders() -> None:
    env = (
        "DB_PASSWORD=",
        "APP_ENV=prod",
        "DB_PASSWORD=${DB_PASSWORD}",
        "API_TOKEN=changeme",
        "DB_PASSWORD=/run/secrets/db",
        "NOEQUALS",
    )
    assert list(secret_in_env([make(env=env)])) == []


def test_secret_in_env_matches_key_suffix() -> None:
    findings = list(secret_in_env([make(env=("SIGNING_KEY=abcdef",))]))
    assert [f.evidence for f in findings] == ["SIGNING_KEY=ab***"]


def test_unpinned_image() -> None:
    digest = "nginx@sha256:" + "a" * 64
    assert len(list(unpinned_image([make(image="nginx:latest")]))) == 1
    assert len(list(unpinned_image([make(image="nginx")]))) == 1
    assert len(list(unpinned_image([make(image="localhost:5000/app")]))) == 1
    assert list(unpinned_image([make(image=digest)])) == []
    assert list(unpinned_image([make(image="nginx:1.27")])) == []
    assert list(unpinned_image([make(image="localhost:5000/app:2.0")])) == []
