"""Collect container data from the Docker CLI (read-only). Implemented by agent A."""

from __future__ import annotations

from ca.models import Container


def parse_inspect(objects: list[dict]) -> list[Container]:
    """Parse a list of `docker inspect` JSON objects into Container models."""
    raise NotImplementedError
