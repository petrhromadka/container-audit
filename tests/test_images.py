from __future__ import annotations

from dataclasses import replace
from datetime import date

import pytest

from ca.checks import images
from ca.collect import parse_inspect
from ca.models import Severity

TODAY = date(2026, 11, 5)


@pytest.fixture(autouse=True)
def _fixed_today(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(images, "_today", lambda: TODAY)


def _container(created: str):
    [c] = parse_inspect([{"Id": "c1", "Name": "/app", "Image": "sha256:img"}])
    return replace(c, image_created=created)


@pytest.mark.parametrize(
    ("created", "flagged"),
    [
        ("2023-01-15T08:30:00.123456789Z", True),  # docker's nanosecond timestamps
        ("2026-05-08T00:00:00Z", True),  # 181 days
        ("2026-05-09T00:00:00Z", False),  # exactly 180 days
        ("2026-10-01T00:00:00Z", False),
        ("1970-01-01T00:00:00Z", False),  # reproducible build epoch, age unknown
        ("", False),  # image data not collected
        ("garbage", False),
    ],
)
def test_stale_image(created: str, flagged: bool) -> None:
    findings = list(images.stale_image([_container(created)]))
    assert bool(findings) is flagged
    if flagged:
        assert findings[0].check_id == "stale-image"
        assert findings[0].severity is Severity.MEDIUM


def test_parse_inspect_uses_image_objects_only_for_build_time() -> None:
    objects = [
        {"Id": "c1", "Name": "/app", "Image": "sha256:img"},
        {"Id": "sha256:img", "Created": "2024-01-02T00:00:00Z", "RootFS": {"Type": "layers"}},
    ]
    [container] = parse_inspect(objects)
    assert container.image_created == "2024-01-02T00:00:00Z"
