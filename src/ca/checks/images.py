"""Image freshness: images built long ago likely miss upstream security patches."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, date, datetime

from ca.models import CheckFn, Container, Finding, Severity

MAX_IMAGE_AGE_DAYS = 180
# Reproducible builds (distroless, ko, Nix) stamp a fixed epoch date; that is not a real age.
_EARLIEST_REAL_BUILD = date(2000, 1, 1)


def _today() -> date:
    return datetime.now(UTC).date()


def _build_date(created: str) -> date | None:
    try:
        built = date.fromisoformat(created[:10])
    except ValueError:
        return None
    return built if built >= _EARLIEST_REAL_BUILD else None


def stale_image(containers: list[Container]) -> Iterable[Finding]:
    today = _today()
    for c in containers:
        built = _build_date(c.image_created)
        if built is None:
            continue
        age = (today - built).days
        if age > MAX_IMAGE_AGE_DAYS:
            yield Finding(
                check_id="stale-image",
                title="Image was built long ago",
                severity=Severity.MEDIUM,
                container=c.name,
                detail=f"The image is {age} days old, so it likely lacks security patches "
                "released since it was built.",
                evidence=f"image built {built.isoformat()} ({age} days ago)",
                remediation="Pull or rebuild the image on a current base and recreate the "
                "container; automate updates (e.g. Renovate, Dependabot).",
            )


CHECKS: list[CheckFn] = [stale_image]
