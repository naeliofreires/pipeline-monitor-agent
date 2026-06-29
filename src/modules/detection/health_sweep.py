from __future__ import annotations

from typing import Any

from modules.detection.anomaly import Anomaly
from modules.parsing import get_value, optional_int


def detect_unhealthy_flows(health_entries: list[Any] | None, existing_flow_ids: set[int] | None = None) -> list[Anomaly]:
    existing = existing_flow_ids or set()
    seen: set[int] = set()
    anomalies: list[Anomaly] = []
    for entry in health_entries or []:
        flow_id = optional_int(get_value(entry, "flow_id", get_value(entry, "id", get_value(entry, "origin_node_id"))))
        if flow_id is None or flow_id in existing or flow_id in seen:
            continue
        seen.add(flow_id)
        name = get_value(entry, "flow_name", get_value(entry, "name"))
        message = get_value(entry, "errorSummary", get_value(entry, "error_summary", "Flow health is RED"))
        anomalies.append(Anomaly(0, "health_sweep", flow_id, name, "ERROR", None, "flow", str(message or "Flow health is RED"), None))
    return anomalies
