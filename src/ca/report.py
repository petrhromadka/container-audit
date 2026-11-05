"""Render a Report as text / json / markdown. Implemented by agent D."""

from __future__ import annotations

from ca.models import Report


def render(report: Report, fmt: str = "text") -> str:
    raise NotImplementedError
