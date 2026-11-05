"""Redaction helpers shared by checks so no secret value ever reaches output."""

from __future__ import annotations


def mask(value: str, keep: int = 2) -> str:
    """Mask a sensitive value, keeping at most `keep` leading chars.

    >>> mask("supersecret")
    'su***'
    >>> mask("")
    '***'
    """
    value = value.strip()
    if len(value) <= keep:
        return "***"
    return f"{value[:keep]}***"
