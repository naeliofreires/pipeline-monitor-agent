from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from modules.detection.anomaly import Anomaly


class AnomalyEnricher(Protocol):
    def get_flow_health(self, flow_id: int) -> dict[str, Any] | None: ...
    def get_run_status(self, flow_id: int, run_id: Any) -> dict[str, Any] | None: ...
    def get_flow_error_logs(self, flow_id: int, run_id: Any, limit: int = 5) -> list[Any] | None: ...
    def get_run_metrics(
        self,
        flow_id: int,
        resource_type: str | None = None,
        resource_id: int | None = None,
        run_id: Any | None = None,
    ) -> dict[str, Any] | None: ...
    def get_run_summary(
        self,
        flow_id: int,
        resource_type: str | None = None,
        resource_id: int | None = None,
        run_id: Any | None = None,
    ) -> list[dict[str, Any]] | dict[str, Any] | None: ...


@dataclass(frozen=True)
class Evidence:
    health_status: str | None = None
    flow_status: str | None = None
    run_status: str | None = None
    latest_run_id: Any | None = None
    records_this_run: int | None = None
    errors_this_run: int | None = None
    error_summary: str | None = None
    top_error_logs: tuple[str, ...] = ()
    recent_run_count: int | None = None
    avg_records_previous_runs: float | None = None
    latest_records_from_summary: int | None = None
    record_drop_pct: float | None = None
    latest_errors_from_summary: int | None = None
    consecutive_failed_runs: int | None = None
    recent_run_log_check: str | None = None
    partial: bool = False


def _first(data: dict[str, Any] | None, *keys: str) -> Any:
    if not data:
        return None
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


def _coalesce(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _short_log(entry: Any) -> str:
    if isinstance(entry, dict):
        parts = [entry.get("timestamp"), entry.get("level"), entry.get("message")]
        return " ".join(str(p) for p in parts if p)[:300]
    return str(entry)[:300]


def _to_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _records(row: dict[str, Any]) -> int | None:
    return _to_int(_first(row, "records", "record_count", "recordCount", "output_records", "outputRecords", "latestRecordCount"))


def _errors(row: dict[str, Any]) -> int | None:
    return _to_int(_first(row, "errors", "error_count", "errorCount", "latestErrorCount"))


def _run_status(row: dict[str, Any]) -> str | None:
    value = _first(row, "status", "runStatus", "run_status", "state")
    return str(value).strip().upper() if value is not None else None


def _health_status(row: dict[str, Any] | None) -> str | None:
    value = _first(row, "healthStatus", "health_status")
    return str(value) if value is not None else None


def _flow_status(row: dict[str, Any] | None) -> str | None:
    value = _first(row, "flowStatus", "flow_status", "state")
    if value is not None:
        return str(value).strip().upper()
    status = _first(row, "status")
    if isinstance(status, str) and not status.isdigit():
        return status.strip().upper()
    return str(value).strip().upper() if value is not None else None


def _run_sort_key(row: dict[str, Any]) -> str:
    value = _first(row, "start_time", "startTime", "end_time", "endTime", "runId", "run_id", "runid", "id")
    return str(value) if value is not None else ""


def _summary_rows(summary: list[dict[str, Any]] | dict[str, Any] | None) -> list[dict[str, Any]]:
    if isinstance(summary, list):
        return [row for row in summary if isinstance(row, dict)]
    if not isinstance(summary, dict):
        return []
    for key in ("run_summary", "runSummary", "summary", "data", "items", "runs", "metrics"):
        value = summary.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
        if isinstance(value, dict):
            nested = _summary_rows(value)
            if nested:
                return nested
    mapped_rows = [row for row in summary.values() if isinstance(row, dict)]
    if mapped_rows:
        return mapped_rows
    return []


def _historical_summary(summary: list[dict[str, Any]] | dict[str, Any] | None, latest_run_id: Any | None) -> dict[str, Any]:
    rows = sorted(_summary_rows(summary), key=_run_sort_key, reverse=True)
    if not rows:
        return {}
    latest = None
    if latest_run_id is not None:
        expected = str(latest_run_id)
        for row in rows:
            if str(_first(row, "runId", "run_id", "runid", "id")) == expected:
                latest = row
                break
    if latest is None:
        latest = rows[0]
    ordered_for_streak = [latest] + [row for row in rows if row is not latest]
    latest_records = _records(latest)
    latest_errors = _errors(latest)
    latest_status = _run_status(latest)
    previous_records = [_records(row) for row in rows if row is not latest]
    previous_records = [value for value in previous_records if value is not None]
    avg_previous = (sum(previous_records) / len(previous_records)) if previous_records else None
    drop_pct = None
    if latest_records is not None and avg_previous and avg_previous > 0:
        drop_pct = round(((avg_previous - latest_records) / avg_previous) * 100, 2)
    failed = 0
    for row in ordered_for_streak:
        if _run_status(row) in {"FAILED", "ERROR", "FAILURE"}:
            failed += 1
        else:
            break
    return {
        "recent_run_count": len(rows),
        "avg_records_previous_runs": avg_previous,
        "latest_records_from_summary": latest_records,
        "latest_status_from_summary": latest_status,
        "record_drop_pct": drop_pct,
        "latest_errors_from_summary": latest_errors,
        "consecutive_failed_runs": failed,
    }


def _recent_run_ids(summary: list[dict[str, Any]] | dict[str, Any] | None, latest_run_id: Any | None, limit: int = 5) -> list[Any]:
    rows = sorted(_summary_rows(summary), key=_run_sort_key, reverse=True)
    ids: list[Any] = []
    if latest_run_id is not None:
        ids.append(latest_run_id)
    for row in rows:
        value = _first(row, "runId", "run_id", "runid", "id")
        if value is not None and str(value) not in {str(existing) for existing in ids}:
            ids.append(value)
        if len(ids) >= limit:
            break
    return ids


def enrich_anomaly(anomaly: Anomaly, nexla_adapter: AnomalyEnricher) -> Evidence:
    if anomaly.flow_id is None:
        return Evidence(partial=True)

    partial = False
    try:
        health = nexla_adapter.get_flow_health(anomaly.flow_id)
    except Exception:
        health = None
    if health is None:
        partial = True
    latest_run_id = _first(health, "latestRunId", "latest_run_id", "run_id")
    run_status = metrics = run_summary = None
    logs: list[Any] | None = []
    log_check_inconclusive = False
    if latest_run_id is None:
        partial = True
    else:
        try:
            run_status = nexla_adapter.get_run_status(anomaly.flow_id, latest_run_id)
        except Exception:
            run_status = None
        try:
            metrics = nexla_adapter.get_run_metrics(anomaly.flow_id, anomaly.resource_type, anomaly.resource_id, latest_run_id)
        except Exception:
            metrics = None
        try:
            run_summary = nexla_adapter.get_run_summary(anomaly.flow_id, anomaly.resource_type, anomaly.resource_id, latest_run_id)
        except Exception:
            run_summary = None
        try:
            log_run_ids = _recent_run_ids(run_summary, latest_run_id)
            logs = nexla_adapter.get_flow_error_logs(anomaly.flow_id, log_run_ids or latest_run_id, limit=5)
        except Exception:
            logs = None
            partial = True
        if logs is None:
            logs = []
            log_check_inconclusive = True
            partial = True
        if run_status is None or metrics is None:
            partial = True

    historical = _historical_summary(run_summary, latest_run_id)
    if log_check_inconclusive:
        recent_run_log_check = "inconclusive: unable to check Nexla ERROR logs for the latest/recent runs"
    elif logs:
        recent_run_log_check = "anomalies_found: Nexla ERROR logs were found for the latest/recent runs"
    elif latest_run_id is not None:
        recent_run_log_check = "none_found: no Nexla ERROR log anomalies were found for the latest/recent runs"
    else:
        recent_run_log_check = "inconclusive: latest run was unavailable for Nexla ERROR log check"
    return Evidence(
        health_status=_health_status(health),
        flow_status=_flow_status(health),
        run_status=_coalesce(_first(run_status, "status", "runStatus", "run_status"), historical.get("latest_status_from_summary")),
        latest_run_id=latest_run_id,
        records_this_run=_coalesce(_first(metrics, "records", "record_count", "latestRecordCount"), _first(health, "latestRecordCount"), historical.get("latest_records_from_summary")),
        errors_this_run=_coalesce(_first(metrics, "errors", "error_count", "latestErrorCount"), _first(health, "latestErrorCount"), historical.get("latest_errors_from_summary")),
        error_summary=_first(health, "errorSummary", "error_summary"),
        top_error_logs=tuple(_short_log(log) for log in logs[:5]),
        recent_run_count=historical.get("recent_run_count"),
        avg_records_previous_runs=historical.get("avg_records_previous_runs"),
        latest_records_from_summary=historical.get("latest_records_from_summary"),
        record_drop_pct=historical.get("record_drop_pct"),
        latest_errors_from_summary=historical.get("latest_errors_from_summary"),
        consecutive_failed_runs=historical.get("consecutive_failed_runs"),
        recent_run_log_check=recent_run_log_check,
        partial=partial,
    )
