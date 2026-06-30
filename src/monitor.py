from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from adapters.llm_factory import build_llm_adapter
from adapters.nexla_adapter import NexlaAdapter
from config import get_nested, require_str
from modules.alerting.alert import build_anomaly_alert_text, wrap_explanation
from modules.alerting.sender import AlertSender, build_alert_sender
from modules.classification.classifier import classify_anomaly
from modules.detection.anomaly import Anomaly
from modules.detection.explicit_failure import detect_explicit_failures, is_explicit_failure_notification
from modules.detection.health_sweep import detect_unhealthy_flows
from modules.detection.silent_failure import (
    DEFAULT_MIN_BASELINE_RECORDS,
    DEFAULT_VOLUME_THRESHOLD_PCT,
    build_run_observations,
    detect_run_drop_failures,
    extract_flow_volumes,
)
from modules.enrichment.enricher import Evidence, enrich_anomaly
from modules.parsing import get_value
from modules.suppression.suppression import note_alerted, should_alert
from modules.controls.policy import ControlMetadata
from repositories.snapshot_repository import SnapshotRepository
from repositories.suppression_repository import SuppressionRepository
from repositories.monitored_flow_repository import MonitoredFlowRepository, RunSnapshot

logger = logging.getLogger(__name__)

# Metric snapshots older than this are purged each tick; run-over-run only needs the most
# recent prior snapshot, the extra days leave room for a future rolling baseline.
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


def build_monitored_flow_repository(config: dict[str, Any]) -> MonitoredFlowRepository:
    """Build the SQLite-backed store for user-registered continuous Flow monitoring."""
    db_path = get_nested(config, ("monitoring", "state_db_path"), "data/state.db")
    return MonitoredFlowRepository(str(db_path))


def handle_monitoring_command(
    config: dict[str, Any], action: str, flow_id: int | None, metadata: dict[str, str | None]
) -> str:
    """Register, remove, or list continuously monitored Flows for a Slack channel."""
    channel_id = metadata.get("channel_id")
    if not channel_id:
        return "Cannot update monitoring without a Slack channel ID."
    repo = build_monitored_flow_repository(config)
    try:
        if action == "register":
            if flow_id is None:
                return "Missing Flow ID."
            repo.register_flow(flow_id, channel_id, metadata.get("user_id"), datetime.now(timezone.utc))
            return (
                f"Flow {flow_id} is now being monitored in this channel. I’ll post here when a new run is "
                "processed or when a high-risk Anomaly is found."
            )
        if action == "remove":
            if flow_id is None:
                return "Missing Flow ID."
            removed = repo.remove_flow(flow_id, channel_id)
            if removed:
                return f"Flow {flow_id} is no longer monitored in this channel."
            return f"Flow {flow_id} was not being monitored in this channel."
        if action == "list":
            flows = repo.list_flows(channel_id)
            if not flows:
                return "No Flows are currently monitored in this channel."
            ids = ", ".join(str(flow.flow_id) for flow in flows)
            return f"Flows monitored in this channel: {ids}."
        return "Unknown monitoring action."
    finally:
        _close_quietly(repo)


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
    """Flag flows whose latest run moved far fewer records than the previously observed run.

    Run-over-run: ``list_flow_volumes`` reads each flow's current latest-run record count
    (the windowed day-over-day org-health query returns empty against real Nexla, and
    ``latestRecordCount`` is a per-run count, not a window aggregate). The baseline is the
    most recent snapshot for that flow — a prior tick's latest-run count. Pure reads only;
    persisting today's volumes is a separate step in ``monitor_once``. Returns
    ``(anomalies, today_volumes, today)``. Wrapped by the caller so a read failure degrades
    to no Silent Failures.
    """
    threshold_pct = get_nested(config, ("detection", "volume_threshold_pct"), DEFAULT_VOLUME_THRESHOLD_PCT)
    min_baseline = get_nested(config, ("detection", "min_baseline_records"), DEFAULT_MIN_BASELINE_RECORDS)

    today = now.date().isoformat()
    current = extract_flow_volumes(adapter.list_flow_volumes())
    observations = build_run_observations(current, previous_volume=snapshots.get_latest_record_count)
    anomalies = detect_run_drop_failures(
        observations,
        threshold_pct=float(threshold_pct),
        min_baseline=int(min_baseline),
        per_flow_threshold=_per_flow_thresholds(config),
        exclude_flow_ids=exclude_flow_ids,
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


def _scan_log_line(evidence: Any) -> str:
    """Logs line for the scan table — reflects the actual ERROR-log check, not ``partial``."""
    if evidence.top_error_logs or evidence.error_summary:
        return "ERROR log lines found in the latest/recent runs"
    check = evidence.recent_run_log_check or ""
    if check.startswith("none_found"):
        return "No ERROR log lines in the latest/recent runs"
    if check.startswith("inconclusive") or evidence.partial:
        return "Inconclusive (log read failed)"
    return "No critical log lines in supported signals"


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
        f"Logs       : {_scan_log_line(evidence)}",
        f"Anomalies  : {'Detected' if found_anomaly else 'None detected in supported signals'}",
        "```",
    ]
    lines = [line for line in lines if line is not None]
    if anomaly.message:
        lines.append(f"*Scan evidence:* {anomaly.message}")
    lines.append(f"*Result:* {'Anomaly found' if found_anomaly else 'No Anomaly found from the targeted scan signals.'}")
    lines.append(f"*Explanation:* {wrap_explanation(classification.explanation)}")
    if evidence.record_drop_pct is not None:
        lines.append(f"> Recent run-drop evidence: {evidence.record_drop_pct}% below recent run average.")
    lines.append("")
    lines.append("*Next Steps:*")
    lines.append(f"🔹 {wrap_explanation(classification.recommended_action)}")
    if evidence.partial:
        lines.append("⚠ Evidence is partial: some flow data could not be read.")
    return "\n".join(lines)


def _average(values: list[int]) -> float | None:
    return sum(values) / len(values) if values else None


def _pct_delta(current: int | None, baseline: float | None) -> float | None:
    if current is None or baseline is None or baseline <= 0:
        return None
    return (current - baseline) / baseline * 100


def _fmt_number(value: int | float | None) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, float):
        return f"{value:,.1f}"
    return f"{value:,}"


def _fmt_signed_number(value: int | None) -> str:
    if value is None:
        return "unknown"
    return f"{value:+,}"


def _fmt_delta(value: float | None) -> str:
    if value is None:
        return "unknown"
    return f"{value:+.1f}%"


def _records_delta(current: int | None, previous: int | None) -> int | None:
    if current is None or previous is None:
        return None
    return current - previous


def _build_run_report_text(
    *,
    flow_id: int,
    flow_name: str | None,
    run_id: str,
    records: int | None,
    errors: int | None,
    status: str | None,
    previous_runs: list[RunSnapshot],
    avg_records: float | None,
    records_delta_pct: float | None,
    classification: Any | None,
) -> str:
    flow_label = f"{flow_name} ({flow_id})" if flow_name else str(flow_id)
    lines = [
        f"*New run processed for Flow {flow_label}*",
        "",
        f"*Latest run:* {run_id}",
        f"*Records:* {_fmt_number(records)}",
        f"*Errors:* {_fmt_number(errors)}",
        f"*Status:* {status or 'unknown'}",
    ]
    if previous_runs:
        previous_run = previous_runs[0]
        previous_records = previous_run.records
        previous_delta = _records_delta(records, previous_records)
        previous_delta_pct = _pct_delta(records, previous_records)
        lines.extend([
            "",
            f"*Previous run:* {previous_run.run_id}",
            f"*Previous records:* {_fmt_number(previous_records)}",
            f"*Change from previous run:* {_fmt_signed_number(previous_delta)} records "
            f"({_fmt_delta(previous_delta_pct)})",
        ])
    lines.extend([
        "",
        f"*Baseline:* average of the previous 5 runs ({len(previous_runs)} available and used)",
        f"*Average records:* {_fmt_number(avg_records)}",
        f"*Difference:* {_fmt_delta(records_delta_pct)}",
    ])
    if classification is not None and classification.risk_classification == "high":
        lines.extend([
            "",
            "*Risk Classification:* HIGH",
            f"*Explanation:* {wrap_explanation(classification.explanation)}",
            f"*Recommended Action:* {wrap_explanation(classification.recommended_action)}",
        ])
    else:
        lines.extend(["", "*Result:* No high-risk Anomaly found from supported signals."])
    return "\n".join(lines)


def _channel_sender(config: dict[str, Any], channel_id: str) -> AlertSender:
    scoped = dict(config)
    slack = dict(scoped.get("slack", {}) or {})
    slack["channel_id"] = channel_id
    scoped["slack"] = slack
    return build_alert_sender(scoped)


def _registered_flow_anomaly(
    flow_id: int,
    flow_name: str | None,
    resource_id: int | None,
    resource_type: str,
    health_status: str | None,
    records: int | None,
    avg_records: float | None,
    drop_threshold_pct: float,
    now: datetime,
) -> Anomaly | None:
    if _is_unhealthy(health_status):
        return Anomaly(0, "health_sweep", flow_id, flow_name, "WARNING", resource_id, resource_type, "Registered Flow monitoring found unhealthy Flow health.", now)
    if records is None or avg_records is None or avg_records <= 0:
        return None
    drop_pct = (avg_records - records) / avg_records * 100
    if drop_pct < drop_threshold_pct:
        return None
    return Anomaly(
        0,
        "silent_failure",
        flow_id,
        flow_name,
        "WARNING",
        resource_id,
        resource_type,
        f"Latest run processed {drop_pct:.0f}% fewer records than the previous 5-run average ({records} records vs {_fmt_number(avg_records)} average)",
        now,
    )


def _analyze_registered_flows(
    adapter: NexlaAdapter,
    llm_adapter: Any,
    config: dict[str, Any],
    repo: MonitoredFlowRepository,
    now: datetime,
    channel_sender_override: AlertSender | None = None,
) -> None:
    """Post run reports for each registered Flow. Without an override, each Flow's report goes to
    the Slack channel it was registered in. The override (used by the console/chat watcher, whose
    ``channel_id`` is ``"cli"`` rather than a real Slack channel) routes every report to one
    destination instead of attempting a Slack post."""
    recent_run_count = int(get_nested(config, ("monitoring", "registered_flow_recent_run_count"), 5))
    drop_threshold_pct = float(get_nested(config, ("detection", "run_drop_threshold_pct"), DEFAULT_VOLUME_THRESHOLD_PCT))
    for monitored in repo.list_flows():
        try:
            flow_id = monitored.flow_id
            flow = adapter.get_flow(flow_id)
            health = adapter.get_flow_health(flow_id)
            primary_row = _primary_flow_row(flow, flow_id)
            latest_run_id = _flow_get_latest_run(primary_row) or get_value(health, "latestRunId", get_value(health, "latest_run_id"))
            if latest_run_id is None:
                repo.mark_checked(flow_id, monitored.channel_id, now)
                continue
            run_id = str(latest_run_id)
            flow_name = _flow_name(flow, health)
            health_status = str(_flow_get_health_status(health) or "").strip().upper() or None
            flow_status = str(_flow_get_status(primary_row) or "").strip().upper() or None
            resource_type, resource_id = _flow_get_resource(primary_row)

            fallback_health = {"healthStatus": health_status, "status": flow_status, "latestRunId": run_id, "name": flow_name}
            enrich_adapter = _FlowGetFallbackAdapter(adapter, fallback_health)
            probe = Anomaly(0, "flow_scan", flow_id, flow_name, "INFO", resource_id, resource_type, "Registered Flow monitoring run check.", now)
            evidence = enrich_anomaly(probe, enrich_adapter)
            metrics_note = None
            try:
                summary = enrich_adapter.get_run_summary(flow_id, resource_type, resource_id, run_id)
            except Exception:
                summary = None
            evidence, metrics_note = _apply_targeted_metrics_fallback(evidence, summary)
            records = evidence.records_this_run
            errors = evidence.errors_this_run
            status = evidence.run_status

            previous_runs = repo.recent_run_snapshots(flow_id, exclude_run_id=run_id, limit=recent_run_count)
            avg_records = _average([int(snapshot.records) for snapshot in previous_runs if snapshot.records is not None])
            records_delta_pct = _pct_delta(records, avg_records)
            anomaly = _registered_flow_anomaly(flow_id, flow_name, resource_id, resource_type, health_status, records, avg_records, drop_threshold_pct, now)
            classification = classify_anomaly(anomaly, evidence, llm_adapter) if anomaly is not None else None
            is_new_run = monitored.last_seen_run_id != run_id
            should_send_high_risk = classification is not None and classification.risk_classification == "high" and monitored.last_alerted_run_id != run_id

            repo.save_run_snapshot(flow_id, run_id, records, errors, status, now)
            if is_new_run or should_send_high_risk:
                text = _build_run_report_text(
                    flow_id=flow_id,
                    flow_name=flow_name,
                    run_id=run_id,
                    records=records,
                    errors=errors,
                    status=status,
                    previous_runs=previous_runs,
                    avg_records=avg_records,
                    records_delta_pct=records_delta_pct,
                    classification=classification,
                )
                _ = metrics_note
                sender = channel_sender_override or _channel_sender(config, monitored.channel_id)
                sender.send(text, ControlMetadata(flow_id, flow_name, flow_status or health_status))
                repo.mark_checked(
                    flow_id,
                    monitored.channel_id,
                    now,
                    last_seen_run_id=run_id if is_new_run else None,
                    last_alerted_run_id=run_id if should_send_high_risk else None,
                )
            else:
                repo.mark_checked(flow_id, monitored.channel_id, now)
        except Exception:
            logger.warning(
                "Registered Flow monitoring failed for flow %s in channel %s; continuing",
                monitored.flow_id,
                monitored.channel_id,
                exc_info=True,
            )


def latest_runs(config: dict[str, Any], flow_id: int, limit: int = 10) -> str:
    """Read-only: fetch the latest runs for one Flow and return a compact text table."""
    service_key = _required_config_value(config, ("nexla", "service_key"), "Nexla service key")
    adapter = build_nexla_adapter(config, service_key)
    flow = adapter.get_flow(flow_id)
    health = adapter.get_flow_health(flow_id)
    name = _flow_name(flow, health, fallback=f"Flow {flow_id}")
    primary_row = _primary_flow_row(flow, flow_id)
    resource_type, resource_id = _flow_get_resource(primary_row)
    runs = adapter.get_flow_runs(flow_id, resource_type, resource_id, limit)
    if not runs:
        return f"No runs found for {name} (ID {flow_id})."
    header = f"Latest {len(runs)} run(s) for {name} (ID {flow_id}):"
    lines = ["run_id | status | records | errors"]
    for run in runs:
        lines.append(
            f"{run['run_id']} | {run['status'] or 'unknown'} | "
            f"{run['records'] if run['records'] is not None else '-'} | "
            f"{run['errors'] if run['errors'] is not None else '-'}"
        )
    return header + "\n```\n" + "\n".join(lines) + "\n```"


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
    monitored_flows = build_monitored_flow_repository(config)
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

        # When the caller passes an explicit sender (console/chat watcher), route registered-Flow
        # reports there too — their channel_id is "cli", not a real Slack channel. The scheduler
        # passes no sender, so each report keeps going to the Slack channel it was registered in.
        _analyze_registered_flows(
            adapter, llm_adapter, config, monitored_flows, now,
            channel_sender_override=alert_sender,
        )

        # Housekeeping: drop state past its retention horizon so the SQLite file stays small.
        suppression.purge_expired(now)
        snapshots.purge_older_than((now - timedelta(days=SNAPSHOT_RETENTION_DAYS)).date().isoformat())
    finally:
        _close_quietly(suppression)
        _close_quietly(snapshots)
        _close_quietly(monitored_flows)
