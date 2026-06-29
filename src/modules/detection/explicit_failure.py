from __future__ import annotations

from typing import Any

from modules.detection.anomaly import Anomaly
from modules.parsing import get_value, optional_int


def _flow_name(notification: Any) -> str | None:
    for key in ("resource_name", "flow_name", "name"):
        value = get_value(notification, key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def detect_explicit_failures(notifications: list[Any] | None = None, nexla_adapter: Any | None = None) -> list[Anomaly]:
    """Convert unread Nexla notifications into Explicit Failure anomalies."""
    if notifications is None:
        return []

    anomalies: list[Anomaly] = []
    for notification in notifications:
        notification_id = get_value(notification, "id")
        if notification_id is None:
            continue

        resource_id = optional_int(get_value(notification, "resource_id"))
        resource_type = get_value(notification, "resource_type")
        flow_id = nexla_adapter.resolve_flow(resource_type, resource_id) if nexla_adapter and resource_id is not None else None
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
                detected_at=get_value(notification, "created_at"),
            )
        )

    return anomalies
