from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Protocol

from modules.detection.anomaly import Anomaly

logger = logging.getLogger(__name__)


class SuppressionStore(Protocol):
    """Storage for the Suppression Window. Implemented by the Repositories layer."""

    def is_suppressed(self, flow_id: int, anomaly_type: str, now: datetime) -> bool: ...

    def record_alert(
        self, flow_id: int, anomaly_type: str, alerted_at: datetime, suppressed_until: datetime
    ) -> None: ...


def _blocked_flow_ids(blocklist_entries: list[Any] | None) -> set[int]:
    blocked: set[int] = set()
    for entry in blocklist_entries or []:
        flow_id = entry.get("flow_id") if isinstance(entry, dict) else getattr(entry, "flow_id", None)
        if flow_id is not None:
            blocked.add(int(flow_id))
    return blocked


def is_blocked(anomaly: Anomaly, blocklist_entries: list[Any] | None) -> bool:
    """True if the anomaly's flow is on the operator Blocklist in ``config.yaml``."""
    return anomaly.flow_id is not None and anomaly.flow_id in _blocked_flow_ids(blocklist_entries)


def should_alert(
    anomaly: Anomaly,
    store: SuppressionStore,
    now: datetime,
    blocklist_entries: list[Any] | None = None,
) -> bool:
    """Decide whether to alert: drop blocklisted flows and those inside a live Suppression Window.

    Anomalies without a resolved ``flow_id`` cannot be keyed for suppression and are allowed
    through — Explicit Failures in that state are still deduped by Nexla's notification read flag.
    """
    if is_blocked(anomaly, blocklist_entries):
        logger.debug("Skipping blocklisted flow %s (%s)", anomaly.flow_id, anomaly.type)
        return False
    if anomaly.flow_id is None:
        return True
    if store.is_suppressed(anomaly.flow_id, anomaly.type, now):
        logger.debug("Suppressing repeat alert for flow %s (%s)", anomaly.flow_id, anomaly.type)
        return False
    return True


def note_alerted(
    anomaly: Anomaly, store: SuppressionStore, now: datetime, window_hours: float
) -> None:
    """Record that an Alert was emitted so the same flow/type is suppressed for the window."""
    if anomaly.flow_id is None:
        return
    suppressed_until = now + timedelta(hours=float(window_hours))
    store.record_alert(anomaly.flow_id, anomaly.type, now, suppressed_until)
