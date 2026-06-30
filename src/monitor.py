from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from adapters.llm_factory import build_llm_adapter
from adapters.nexla_adapter import NexlaAdapter
from config import get_nested, require_str
from modules.alerting.alert import build_anomaly_alert_text
from modules.alerting.sender import AlertSender, build_alert_sender
from modules.classification.classifier import classify_anomaly
from modules.detection.anomaly import Anomaly
from modules.detection.explicit_failure import detect_explicit_failures, is_explicit_failure_notification
from modules.detection.health_sweep import detect_unhealthy_flows
from modules.detection.silent_failure import (
    DEFAULT_MIN_BASELINE_RECORDS,
    DEFAULT_RUN_DROP_THRESHOLD_PCT,
    DEFAULT_VOLUME_THRESHOLD_PCT,
    build_run_observations,
    build_observations,
    detect_run_drop_failures,
    detect_silent_failures,
    extract_flow_volumes,
)
from modules.enrichment.enricher import Evidence, enrich_anomaly
from modules.parsing import get_value
from modules.suppression.suppression import note_alerted, should_alert
from modules.controls.policy import ControlMetadata
from repositories.snapshot_repository import SnapshotRepository
from repositories.suppression_repository import SuppressionRepository

logger = logging.getLogger(__name__)

# Metric snapshots older than this are purged each tick; day-over-day comparison only
# needs yesterday, the extra days leave room for a future rolling baseline.
SNAPSHOT_RETENTION_DAYS = 7
UNHEALTHY_STATUSES = {"RED", "FAILED", "ERROR", "UNHEALTHY"}


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


def _per_flow_run_drop_thresholds(config: dict[str, Any]) -> dict[int, float]:
    overrides: dict[int, float] = {}
    for entry in get_nested(config, ("detection", "flows")) or []:
        flow_id = entry.get("flow_id") if isinstance(entry, dict) else getattr(entry, "flow_id", None)
        threshold = (
            entry.get("run_drop_threshold_pct") if isinstance(entry, dict)
            else getattr(entry, "run_drop_threshold_pct", None)
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
    run_drop_threshold_pct = get_nested(
        config, ("detection", "run_drop_threshold_pct"), DEFAULT_RUN_DROP_THRESHOLD_PCT
    )
    min_run_baseline = get_nested(config, ("detection", "min_run_baseline_records"), min_baseline)

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
    run_exclusions = exclude_flow_ids | {anomaly.flow_id for anomaly in anomalies if anomaly.flow_id is not None}
    run_observations = build_run_observations(
        current, previous_volume=lambda flow_id: snapshots.get_record_count(flow_id, today)
    )
    anomalies.extend(
        detect_run_drop_failures(
            run_observations,
            threshold_pct=float(run_drop_threshold_pct),
            min_baseline=int(min_run_baseline),
            per_flow_threshold=_per_flow_run_drop_thresholds(config),
            exclude_flow_ids=run_exclusions,
        )
    )
    return anomalies, current, today


def _flow_name(flow: Any, health: Any, fallback: str | None = None) -> str | None:
    for source in (_primary_flow_row(flow, None), flow, health):
        if isinstance(source, dict):
            value = get_value(source, "flow_name", get_value(source, "name"))
            if value:
                return str(value)
    return fallback


def _primary_flow_row(flow: Any, flow_id: int | None) -> dict[str, Any] | None:
    if not isinstance(flow, dict):
        return None
    rows = flow.get("flows")
    if isinstance(rows, list):
        candidates = [row for row in rows if isinstance(row, dict)]
        if flow_id is not None:
            for row in candidates:
                if get_value(row, "id") == flow_id or get_value(row, "origin_node_id") == flow_id:
                    return row
        return candidates[0] if candidates else None
    return flow


def _flow_get_latest_run(row: dict[str, Any] | None) -> Any:
    return get_value(row, "latestRunId", get_value(row, "latest_run_id", get_value(row, "run_id", get_value(row, "last_run_id"))))


def _flow_get_health_status(health: Any) -> Any:
    return get_value(health, "healthStatus", get_value(health, "health_status"))


def _flow_get_status(row: dict[str, Any] | None) -> Any:
    return get_value(row, "status", get_value(row, "state", get_value(row, "flow_status", get_value(row, "flowStatus", get_value(row, "runtime_status")))))


def _current_flow_status(adapter: NexlaAdapter, flow_id: int | None, fallback: str | None = None) -> str | None:
    if flow_id is None:
        return fallback
    try:
        flow = adapter.get_flow(flow_id)
    except Exception:
        return fallback
    row = _primary_flow_row(flow, flow_id)
    status = get_value(row, "status", get_value(row, "state", get_value(row, "flow_status", get_value(row, "flowStatus", get_value(row, "runtime_status")))))
    return str(status).strip().upper() if status is not None else fallback


def _flow_get_resource(row: dict[str, Any] | None) -> tuple[str, int | None]:
    for key, resource_type in (("data_source_id", "data_source"), ("data_set_id", "data_set"), ("data_sink_id", "data_sink")):
        value = get_value(row, key)
        if value is not None:
            return resource_type, int(value)
    return "flow", None


class _FlowGetFallbackAdapter:
    def __init__(self, adapter: NexlaAdapter, fallback_health: dict[str, Any]) -> None:
        self.adapter = adapter
        self.fallback_health = fallback_health

    def get_flow_health(self, flow_id: int) -> dict[str, Any] | None:
        health = self.adapter.get_flow_health(flow_id)
        if not isinstance(health, dict):
            return self.fallback_health
        merged = dict(self.fallback_health)
        for key, value in health.items():
            if value is None:
                continue
            if key == "status" and not (isinstance(value, str) and not value.isdigit()):
                continue
            merged[key] = value
        return merged

    def get_run_status(self, flow_id: int, run_id: Any) -> dict[str, Any] | None:
        return self.adapter.get_run_status(flow_id, run_id)

    def get_flow_error_logs(self, flow_id: int, run_id: Any, limit: int = 5) -> list[Any] | None:
        return self.adapter.get_flow_error_logs(flow_id, run_id, limit)

    def get_run_metrics(self, flow_id: int, resource_type: str | None = None, resource_id: int | None = None, run_id: Any | None = None) -> dict[str, Any] | None:
        return self.adapter.get_run_metrics(flow_id, resource_type, resource_id, run_id)

    def get_run_summary(self, flow_id: int, resource_type: str | None = None, resource_id: int | None = None, run_id: Any | None = None) -> list[dict[str, Any]] | dict[str, Any] | None:
        return self.adapter.get_run_summary(flow_id, resource_type, resource_id, run_id)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.adapter, name)


def _is_unhealthy(status: str | None) -> bool:
    return bool(status and str(status).strip().upper() in UNHEALTHY_STATUSES)


def _targeted_volume_anomaly(adapter: NexlaAdapter, snapshots: SnapshotRepository, config: dict[str, Any], flow_id: int, now: datetime) -> Anomaly | None:
    try:
        anomalies, _today_volumes, _today = _scan_silent_failures(adapter, snapshots, config, now, set())
    except Exception:
        logger.warning("Targeted Flow scan volume comparison failed for flow %s", flow_id, exc_info=True)
        return None
    return next((anomaly for anomaly in anomalies if anomaly.flow_id == flow_id), None)


def _targeted_metric_rows(summary: Any) -> list[dict[str, Any]]:
    if isinstance(summary, list):
        return [row for row in summary if isinstance(row, dict)]
    if not isinstance(summary, dict):
        return []
    for key in ("run_summary", "runSummary", "summary", "data", "items", "runs", "metrics"):
        rows = _targeted_metric_rows(summary.get(key))
        if rows:
            return rows
    return [row for row in summary.values() if isinstance(row, dict)]


def _targeted_row_run_id(row: dict[str, Any]) -> Any:
    return get_value(row, "runId", get_value(row, "run_id", get_value(row, "runid", get_value(row, "id"))))


def _targeted_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _targeted_row_records(row: dict[str, Any]) -> int | None:
    return _targeted_int(get_value(row, "records", get_value(row, "record_count", get_value(row, "recordCount", get_value(row, "output_records", get_value(row, "outputRecords", get_value(row, "latestRecordCount")))))))


def _targeted_row_errors(row: dict[str, Any]) -> int | None:
    return _targeted_int(get_value(row, "errors", get_value(row, "error_count", get_value(row, "errorCount", get_value(row, "latestErrorCount")))) )


def _targeted_row_status(row: dict[str, Any]) -> str | None:
    value = get_value(row, "status", get_value(row, "runStatus", get_value(row, "run_status", get_value(row, "state"))))
    return str(value) if value is not None else None


def _latest_available_metrics(summary: Any, requested_run_id: Any) -> tuple[dict[str, Any], Any] | None:
    rows = sorted(_targeted_metric_rows(summary), key=lambda row: str(_targeted_row_run_id(row) or ""), reverse=True)
    if not rows:
        return None
    latest = rows[0]
    latest_run_id = _targeted_row_run_id(latest)
    if requested_run_id is not None and latest_run_id is not None and str(latest_run_id) != str(requested_run_id):
        return latest, latest_run_id
    return None


def _apply_targeted_metrics_fallback(evidence: Evidence, summary: Any) -> tuple[Evidence, str | None]:
    fallback = _latest_available_metrics(summary, evidence.latest_run_id)
    if fallback is None:
        return evidence, None
    row, metrics_run_id = fallback
    records = _targeted_row_records(row)
    errors = _targeted_row_errors(row)
    return Evidence(
        health_status=evidence.health_status,
        flow_status=evidence.flow_status,
        run_status=_targeted_row_status(row) or evidence.run_status,
        latest_run_id=metrics_run_id,
        records_this_run=records if records is not None else evidence.records_this_run,
        errors_this_run=errors if errors is not None else evidence.errors_this_run,
        error_summary=evidence.error_summary,
        top_error_logs=evidence.top_error_logs,
        recent_run_count=evidence.recent_run_count,
        avg_records_previous_runs=evidence.avg_records_previous_runs,
        latest_records_from_summary=evidence.latest_records_from_summary,
        record_drop_pct=evidence.record_drop_pct,
        latest_errors_from_summary=evidence.latest_errors_from_summary,
        consecutive_failed_runs=evidence.consecutive_failed_runs,
        recent_run_log_check=evidence.recent_run_log_check,
        partial=evidence.partial,
    ), f"Metrics Run: {metrics_run_id} (latest available; Flow last_run_id is {evidence.latest_run_id})"


def build_flow_scan_text(anomaly: Anomaly, evidence: Any, classification: Any, *, found_anomaly: bool, metrics_note: str | None = None) -> str:
    flow = anomaly.flow_name or anomaly.flow_id or "unknown flow"
    flow_id = anomaly.flow_id or "unknown"
    records = evidence.records_this_run if evidence.records_this_run is not None else "?"
    errors = evidence.errors_this_run if evidence.errors_this_run is not None else "?"
    latest_run = evidence.latest_run_id if evidence.latest_run_id is not None else "unknown"
    risk_icon = {"high": "🔴", "low": "🟡", "unknown": "⚪"}.get(classification.risk_classification, "⚪")
    risk_reason = "Incomplete Evidence" if evidence.partial else ("Anomaly Found" if found_anomaly else "No Supported Anomaly")
    lines = [
        f"*🚦 Flow Health Status | ID: {flow_id} [{classification.risk_classification.upper()}]*",
        f"*Flow:* {flow}",
        f"*Risk Level:* {risk_icon} {classification.risk_classification.upper()} ({risk_reason})",
        "",
        "*Scan Result:*",
        "```",
        f"Health     : {evidence.health_status or 'unknown'}",
        f"Status     : {evidence.flow_status or 'unknown'}",
        f"Latest Run : {latest_run} ({evidence.run_status or 'unknown'})",
        metrics_note,
        f"Records    : {records}",
        f"Errors     : {errors}",
        f"Logs       : {'Inconclusive (read failed)' if evidence.partial else 'No critical log lines in supported signals'}",
        f"Anomalies  : {'Detected' if found_anomaly else 'None detected in supported signals'}",
        "```",
    ]
    lines = [line for line in lines if line is not None]
    if evidence.record_drop_pct is not None:
        lines.append(f"Recent run-drop evidence: {evidence.record_drop_pct}% below recent run average.")
    if anomaly.message:
        lines.append(f"*Scan evidence:* {anomaly.message}")
    lines.append(f"*Result:* {'Anomaly found' if found_anomaly else 'No Anomaly found from the targeted scan signals.'}")
    lines.append(f"*Explanation:* {classification.explanation}")
    lines.append("")
    lines.append("*Next Steps:*")
    lines.append(f"🔹 {classification.recommended_action}")
    if evidence.partial:
        lines.append("⚠ Evidence is partial: some flow data could not be read.")
    return "\n".join(lines)


def scan_flow(config: dict[str, Any], flow_id: int) -> str:
    """Run a read-only targeted analysis for one Flow and return Slack-ready text."""
    service_key = _required_config_value(config, ("nexla", "service_key"), "Nexla service key")
    adapter = build_nexla_adapter(config, service_key)
    llm_adapter = build_llm_adapter(config)
    snapshots = build_snapshot_repository(config)
    now = datetime.now(timezone.utc)
    try:
        flow = adapter.get_flow(flow_id)
        health = adapter.get_flow_health(flow_id)
        primary_row = _primary_flow_row(flow, flow_id)
        latest_run_id = _flow_get_latest_run(primary_row)
        if latest_run_id is None:
            logger.info(
                "Targeted Flow scan could not resolve latest run for flow %s; flow payload keys=%s row keys=%s",
                flow_id,
                sorted(flow.keys()) if isinstance(flow, dict) else [],
                sorted(primary_row.keys()) if isinstance(primary_row, dict) else [],
            )
        health_status = str(_flow_get_health_status(health) or "").strip().upper()
        flow_status = str(_flow_get_status(primary_row) or "").strip().upper()
        resource_type, resource_id = _flow_get_resource(primary_row)
        fallback_health = {
            "healthStatus": health_status or None,
            "status": flow_status or None,
            "latestRunId": latest_run_id,
            "name": _flow_name(flow, health),
        }
        enrich_adapter = _FlowGetFallbackAdapter(adapter, fallback_health)
        volume_anomaly = _targeted_volume_anomaly(adapter, snapshots, config, flow_id, now)
        if volume_anomaly is not None:
            anomaly = Anomaly(volume_anomaly.notification_id, volume_anomaly.type, volume_anomaly.flow_id, volume_anomaly.flow_name or _flow_name(flow, health), volume_anomaly.level, resource_id, resource_type, volume_anomaly.message, volume_anomaly.detected_at)
            found_anomaly = True
        else:
            found_anomaly = _is_unhealthy(health_status)
            anomaly = Anomaly(
                0,
                "health_sweep" if found_anomaly else "flow_scan",
                flow_id,
                _flow_name(flow, health),
                "INFO",
                resource_id,
                resource_type,
                "Targeted scan found unhealthy Flow health." if found_anomaly else "Targeted scan completed; no Anomaly found from supported scan signals.",
                now,
            )
        if anomaly.flow_name is None:
            anomaly = Anomaly(anomaly.notification_id, anomaly.type, anomaly.flow_id, _flow_name(flow, health), anomaly.level, anomaly.resource_id, anomaly.resource_type, anomaly.message, anomaly.detected_at)
        evidence = enrich_anomaly(anomaly, enrich_adapter)
        metrics_note = None
        summary = enrich_adapter.get_run_summary(flow_id, anomaly.resource_type, anomaly.resource_id, evidence.latest_run_id)
        evidence, metrics_note = _apply_targeted_metrics_fallback(evidence, summary)
        if evidence.latest_run_id is not None and (
            evidence.run_status is None or evidence.records_this_run is None or evidence.errors_this_run is None
        ):
            logger.info(
                "Targeted Flow scan has partial run Evidence for flow %s run %s resource=%s/%s run_status=%s records=%s errors=%s logs=%s",
                flow_id,
                evidence.latest_run_id,
                anomaly.resource_type,
                anomaly.resource_id,
                evidence.run_status is not None,
                evidence.records_this_run is not None,
                evidence.errors_this_run is not None,
                evidence.recent_run_log_check,
            )
        classification = classify_anomaly(anomaly, evidence, llm_adapter)
        return build_flow_scan_text(anomaly, evidence, classification, found_anomaly=found_anomaly, metrics_note=metrics_note)
    finally:
        _close_quietly(snapshots)


def monitor_once(config: dict[str, Any], alert_sender: AlertSender | None = None) -> None:
    """Run one monitoring tick: Explicit Failures, the health sweep, and Silent Failures."""
    service_key = _required_config_value(config, ("nexla", "service_key"), "Nexla service key")
    adapter = build_nexla_adapter(config, service_key)
    llm_adapter = build_llm_adapter(config)

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
        ignored_notification_ids = {
            int(notification_id)
            for notification in notifications or []
            if (notification_id := get_value(notification, "id")) is not None
            and not is_explicit_failure_notification(notification)
        }
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

        notification_ids_to_mark_read: set[int] = set(ignored_notification_ids)

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
                    flow_status = _current_flow_status(adapter, anomaly.flow_id, evidence.flow_status or evidence.health_status)
                    sender.send(build_anomaly_alert_text(anomaly, evidence, classification), ControlMetadata(anomaly.flow_id, anomaly.flow_name, flow_status))
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
        adapter.mark_notifications_read(
            [
                notification_id
                for notification_id in sorted(notification_ids_to_mark_read)
                if notification_id in ignored_notification_ids
                or any(a.notification_id == notification_id for a in notification_anomalies)
            ]
        )

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
