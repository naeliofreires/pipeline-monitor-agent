from __future__ import annotations

from typing import Any

from modules.detection.anomaly import Anomaly
from modules.parsing import get_value, optional_int


EXPLICIT_FAILURE_LEVELS = {"ERROR", "CRITICAL", "FATAL"}


def _flow_name(notification: Any) -> str | None:
    for key in ("resource_name", "flow_name", "name"):
        value = get_value(notification, key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _nested_str(source: Any, key: str) -> str | None:
    value = get_value(source, key)
    if isinstance(value, str) and value.strip():
        return value
    return None


def _access_roles(notification: Any) -> tuple[str, ...]:
    roles = get_value(notification, "access_roles", [])
    if not isinstance(roles, list | tuple):
        return ()
    return tuple(str(role) for role in roles if str(role).strip())


def is_explicit_failure_notification(notification: Any) -> bool:
    level = get_value(notification, "level")
    if not isinstance(level, str):
        return False
    return level.strip().upper() in EXPLICIT_FAILURE_LEVELS


def detect_explicit_failures(notifications: list[Any] | None = None, nexla_adapter: Any | None = None) -> list[Anomaly]:
    """Convert unread Nexla notifications into Explicit Failure anomalies."""
    if notifications is None:
        return []

    anomalies: list[Anomaly] = []
    for notification in notifications:
        notification_id = get_value(notification, "id")
        if notification_id is None:
            continue
        if not is_explicit_failure_notification(notification):
            continue

        resource_id = optional_int(get_value(notification, "resource_id"))
        resource_type = get_value(notification, "resource_type")
        flow_id = nexla_adapter.resolve_flow(resource_type, resource_id) if nexla_adapter and resource_id is not None else None
        owner = get_value(notification, "owner", {})
        org = get_value(notification, "org", {})
        created_at = get_value(notification, "created_at")
        anomalies.append(
            Anomaly(
                notification_id=int(notification_id),
                type="explicit_failure",
                flow_id=flow_id,
                flow_name=_flow_name(notification),
                level=get_value(notification, "level"),
                resource_id=resource_id,
                resource_type=resource_type,
                message=str(get_value(notification, "message", "")),
                detected_at=created_at,
                owner_name=_nested_str(owner, "full_name"),
                owner_email=_nested_str(owner, "email"),
                org_name=_nested_str(org, "name"),
                access_roles=_access_roles(notification),
                read_at=get_value(notification, "read_at"),
                created_at=created_at,
                updated_at=get_value(notification, "updated_at"),
            )
        )

    return anomalies
