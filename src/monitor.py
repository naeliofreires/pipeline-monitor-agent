from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from adapters.nexla_adapter import NexlaAdapter
from adapters.opencode_adapter import OpencodeAdapter
from config import get_nested, require_str
from modules.alerting.alert import build_anomaly_alert_text
from modules.alerting.sender import AlertSender, build_alert_sender
from modules.classification.classifier import classify_anomaly
from modules.detection.explicit_failure import detect_explicit_failures
from modules.detection.health_sweep import detect_unhealthy_flows
from modules.detection.silent_failure import (
    DEFAULT_MIN_BASELINE_RECORDS,
    DEFAULT_VOLUME_THRESHOLD_PCT,
    build_observations,
    detect_silent_failures,
    extract_flow_volumes,
)
from modules.enrichment.enricher import enrich_anomaly
from modules.suppression.suppression import note_alerted, should_alert
from modules.controls.policy import ControlMetadata
from repositories.snapshot_repository import SnapshotRepository
from repositories.suppression_repository import SuppressionRepository

logger = logging.getLogger(__name__)

# Metric snapshots older than this are purged each tick; day-over-day comparison only
# needs yesterday, the extra days leave room for a future rolling baseline.
SNAPSHOT_RETENTION_DAYS = 7


class MonitorConfigError(RuntimeError):
    pass


def _close_quietly(repo: Any) -> None:
    """Close a repository, logging (never raising) so one close failure cannot mask another."""
    try:
        repo.close()
    except Exception:
        logger.debug("Failed to close repository", exc_info=True)


def _required_config_value(config: dict[str, Any], path: tuple[str, ...], label: str) -> str:
    return require_str(config, path, f"Missing required config for {label}", MonitorConfigError)


def build_nexla_adapter(config: dict[str, Any], service_key: str) -> NexlaAdapter:
    """Build a NexlaAdapter from config-resolved credentials and optional API URL."""
    return NexlaAdapter(service_key=service_key, api_url=get_nested(config, ("nexla", "api_url")))


def _lookback_timestamp(config: dict[str, Any]) -> int | None:
    hours = get_nested(config, ("monitoring", "notification_lookback_hours"), 24)
    if hours is None:
        return None
    return int((datetime.now(timezone.utc) - timedelta(hours=float(hours))).timestamp())


def build_suppression_repository(config: dict[str, Any]) -> SuppressionRepository:
    """Build the SQLite-backed Suppression Window store from config (or the default path)."""
    db_path = get_nested(config, ("monitoring", "state_db_path"), "data/state.db")
    return SuppressionRepository(str(db_path))


def build_snapshot_repository(config: dict[str, Any]) -> SnapshotRepository:
    """Build the SQLite-backed metric-snapshot store from config (or the default path)."""
    db_path = get_nested(config, ("monitoring", "state_db_path"), "data/state.db")
    return SnapshotRepository(str(db_path))


def _per_flow_thresholds(config: dict[str, Any]) -> dict[int, float]:
    overrides: dict[int, float] = {}
    for entry in get_nested(config, ("detection", "flows")) or []:
        flow_id = entry.get("flow_id") if isinstance(entry, dict) else getattr(entry, "flow_id", None)
        threshold = (
            entry.get("volume_threshold_pct") if isinstance(entry, dict)
            else getattr(entry, "volume_threshold_pct", None)
        )
        if flow_id is not None and threshold is not None:
            overrides[int(flow_id)] = float(threshold)
    return overrides


def _scan_silent_failures(
    adapter: NexlaAdapter,
    snapshots: SnapshotRepository,
    config: dict[str, Any],
    now: datetime,
    exclude_flow_ids: set[int],
) -> tuple[list, dict[int, tuple[str | None, int, str | None]], str]:
    """Read today's vs yesterday's per-flow volume and flag big drops (no writes).

    Returns ``(anomalies, today_volumes, today)``. Pure reads only — persisting
    ``today_volumes`` is a separate step in ``monitor_once`` so this query has no side
    effects. Wrapped by the caller so a read failure degrades to no Silent Failures.
    """
    threshold_pct = get_nested(config, ("detection", "volume_threshold_pct"), DEFAULT_VOLUME_THRESHOLD_PCT)
    min_baseline = get_nested(config, ("detection", "min_baseline_records"), DEFAULT_MIN_BASELINE_RECORDS)

    today = now.date().isoformat()
    yesterday = (now - timedelta(days=1)).date().isoformat()

    current = extract_flow_volumes(adapter.list_flow_volumes(today))
    baseline = extract_flow_volumes(adapter.list_flow_volumes(yesterday))
    observations = build_observations(
        current, baseline, baseline_fallback=lambda flow_id: snapshots.get_record_count(flow_id, yesterday)
    )

    anomalies = detect_silent_failures(
        observations,
        threshold_pct=float(threshold_pct),
        min_baseline=int(min_baseline),
        per_flow_threshold=_per_flow_thresholds(config),
        exclude_flow_ids=exclude_flow_ids,
    )
    return anomalies, current, today


def monitor_once(config: dict[str, Any], alert_sender: AlertSender | None = None) -> None:
    """Run one monitoring tick: Explicit Failures, the health sweep, and Silent Failures."""
    service_key = _required_config_value(config, ("nexla", "service_key"), "Nexla service key")
    adapter = build_nexla_adapter(config, service_key)
    opencode_config = config.get("opencode", {})
    llm_adapter = OpencodeAdapter(
        model=opencode_config.get("model", "big-pickle"),
        base_url=opencode_config.get("base_url", "https://opencode.ai/zen/v1"),
    )

    now = datetime.now(timezone.utc)
    # Repos are built first but everything after runs inside the try so the finally
    # always closes both SQLite connections, even if a detection read raises.
    suppression = build_suppression_repository(config)
    snapshots = build_snapshot_repository(config)
    sender = alert_sender or build_alert_sender(config)
    try:
        blocklist = config.get("blocklist", [])
        window_hours = get_nested(config, ("monitoring", "suppression_window_hours"), 2)

        notifications = adapter.list_unread_notifications(from_timestamp=_lookback_timestamp(config))
        notification_anomalies = detect_explicit_failures(notifications, adapter)
        existing_flow_ids = {a.flow_id for a in notification_anomalies if a.flow_id is not None}
        health_anomalies = detect_unhealthy_flows(adapter.list_unhealthy_flows(), existing_flow_ids)
        existing_flow_ids |= {a.flow_id for a in health_anomalies if a.flow_id is not None}

        try:
            silent_anomalies, today_volumes, today = _scan_silent_failures(
                adapter, snapshots, config, now, existing_flow_ids
            )
        except Exception:
            logger.warning("Silent Failure detection failed this tick; skipping it", exc_info=True)
            silent_anomalies, today_volumes, today = [], {}, now.date().isoformat()
        anomalies = notification_anomalies + health_anomalies + silent_anomalies

        notification_ids_to_mark_read: set[int] = set()

        # Drop blocklisted and still-suppressed anomalies before spending any read/LLM call.
        # Each anomaly is isolated so one failure (e.g. a transient DB lock) does not abort the
        # whole batch or skip the notification read-marking below.
        for anomaly in anomalies:
            try:
                if not should_alert(anomaly, suppression, now, blocklist):
                    if anomaly.type == "explicit_failure" and anomaly.notification_id:
                        notification_ids_to_mark_read.add(anomaly.notification_id)
                    continue
                evidence = enrich_anomaly(anomaly, adapter)
                classification = classify_anomaly(anomaly, evidence, llm_adapter)
                try:
                    sender.send(build_anomaly_alert_text(anomaly, evidence, classification), ControlMetadata(anomaly.flow_id, anomaly.flow_name))
                except TypeError:
                    sender.send(build_anomaly_alert_text(anomaly, evidence, classification))
                note_alerted(anomaly, suppression, now, window_hours)
                if anomaly.type == "explicit_failure" and anomaly.notification_id:
                    notification_ids_to_mark_read.add(anomaly.notification_id)
            except Exception:
                logger.warning(
                    "Failed to process anomaly for flow %s (%s); continuing",
                    anomaly.flow_id,
                    anomaly.type,
                    exc_info=True,
                )

        # Explicit Failure notifications are marked read only after intentional processing:
        # successful Alert send or deliberate suppression/blocklist. Processing failures are left
        # unread so the notification can be retried next tick.
        adapter.mark_notifications_read([a.notification_id for a in notification_anomalies if a.notification_id in notification_ids_to_mark_read])

        # Persist today's volumes (state write, kept separate from the read-only scan above) so the
        # comparison survives an API gap and seeds future baselines.
        for flow_id, (_name, count, _status) in today_volumes.items():
            snapshots.save_snapshot(flow_id, today, count, now)

        # Housekeeping: drop state past its retention horizon so the SQLite file stays small.
        suppression.purge_expired(now)
        snapshots.purge_older_than((now - timedelta(days=SNAPSHOT_RETENTION_DAYS)).date().isoformat())
    finally:
        _close_quietly(suppression)
        _close_quietly(snapshots)
