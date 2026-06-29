from __future__ import annotations

from typing import Any


def get_nested(config: dict[str, Any], path: tuple[str, ...], default: Any = None) -> Any:
    """Safely walk a nested mapping by ``path``, returning ``default`` if any step is missing.

    ``default`` also applies when the final key is absent or present-but-``None``, so a
    caller's default is honored for a missing leaf, not only for a non-dict intermediate.
    """
    current: Any = config
    for part in path:
        if not isinstance(current, dict):
            return default
        current = current.get(part)
    return current if current is not None else default


def require_str(
    config: dict[str, Any],
    path: tuple[str, ...],
    message: str,
    error_cls: type[Exception],
) -> str:
    """Return a non-empty string at ``path`` or raise ``error_cls(message)``."""
    value = get_nested(config, path)
    if not isinstance(value, str) or not value.strip():
        raise error_cls(message)
    return value
