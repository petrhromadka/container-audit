"""Redaction helpers shared by checks so no secret value ever reaches output."""

from __future__ import annotations


def mask(value: str) -> str:
    """Mask a sensitive value without revealing any character of it.

    >>> mask("supersecret")
    '***'
    >>> mask("")
    '***'
    """
    return "***"
