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


@dataclass(frozen=True)
class Evidence:
    health_status: str | None = None
    run_status: str | None = None
    latest_run_id: Any | None = None
    records_this_run: int | None = None
    errors_this_run: int | None = None
    error_summary: str | None = None
    top_error_logs: tuple[str, ...] = ()
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
    run_status = metrics = None
    logs: list[Any] | None = []
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
            logs = nexla_adapter.get_flow_error_logs(anomaly.flow_id, latest_run_id, limit=5)
        except Exception:
            logs = None
            partial = True
        if logs is None:
            logs = []
            partial = True
        if run_status is None or metrics is None:
            partial = True

    return Evidence(
        health_status=_first(health, "healthStatus", "health_status", "status"),
        run_status=_first(run_status, "status", "runStatus", "run_status"),
        latest_run_id=latest_run_id,
        records_this_run=_coalesce(_first(metrics, "records", "record_count", "latestRecordCount"), _first(health, "latestRecordCount")),
        errors_this_run=_coalesce(_first(metrics, "errors", "error_count", "latestErrorCount"), _first(health, "latestErrorCount")),
        error_summary=_first(health, "errorSummary", "error_summary"),
        top_error_logs=tuple(_short_log(log) for log in logs[:5]),
        partial=partial,
    )
