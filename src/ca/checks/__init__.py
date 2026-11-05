"""Check registry. Each submodule exposes `CHECKS: list[CheckFn]`; we aggregate them."""

from __future__ import annotations

from ca.models import CheckFn


def get_checks() -> list[CheckFn]:
    """Every registered check, across all submodules."""
    from ca.checks import exposure, privilege

    return [*privilege.CHECKS, *exposure.CHECKS]
