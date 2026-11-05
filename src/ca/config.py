"""Load optional TOML configuration. Stdlib-only, read-only.

The config file sets defaults for a few CLI options. CLI flags always win
over the file; the file wins over the built-in defaults. See `cli.py` for
how the merge is applied.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

# key -> expected python type. `ignore` is a list of strings, handled separately.
_STR_KEYS = ("min_severity", "fail_on", "format")
_BOOL_KEYS = ("include_host", "include_stopped")
_RECOGNISED = ("ignore", *_STR_KEYS, *_BOOL_KEYS)

_DISCOVERY = ("container-audit.toml", ".container-audit.toml")


def _validate(data: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in data.items():
        if key not in _RECOGNISED:
            raise ValueError(f"unknown config key: {key!r}")
        if key == "ignore":
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ValueError("config key 'ignore' must be a list of strings")
        elif key in _STR_KEYS:
            if not isinstance(value, str):
                raise ValueError(f"config key {key!r} must be a string")
        elif not isinstance(value, bool):  # _BOOL_KEYS
            raise ValueError(f"config key {key!r} must be a boolean")
        result[key] = value
    return result


def load_config(path: str | None, cwd: Path) -> dict[str, Any]:
    """Return recognised config keys from `path`, or auto-discovered file, or {}.

    Raises ValueError on a missing explicit path, malformed TOML, an unknown
    key, or a wrong value type.
    """
    if path is not None:
        config_path: Path | None = Path(path)
    else:
        config_path = next((cwd / name for name in _DISCOVERY if (cwd / name).is_file()), None)
    if config_path is None:
        return {}

    try:
        raw = config_path.read_bytes()
    except FileNotFoundError:
        raise ValueError(f"config file not found: {config_path}") from None
    except OSError as exc:
        raise ValueError(f"cannot read config file ({type(exc).__name__})") from None

    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid config file: {exc}") from None

    return _validate(data)
