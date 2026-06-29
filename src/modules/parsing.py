from __future__ import annotations

from typing import Any

# Small parsing helpers shared across detectors. Nexla payloads arrive as either plain
# dicts or SDK objects, and key names vary (camelCase / snake_case), so detection code
# reaches for the first key that is present.


def get_value(source: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` from a dict or object, falling back to ``default`` when absent."""
    if isinstance(source, dict):
        return source.get(key, default)
    return getattr(source, key, default)


def optional_int(value: Any) -> int | None:
    """Coerce a value to int, preserving None (a missing value stays missing)."""
    if value is None:
        return None
    return int(value)
