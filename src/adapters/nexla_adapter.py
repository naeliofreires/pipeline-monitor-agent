from __future__ import annotations

import logging
from collections.abc import Sized
from typing import Any

try:
    from nexla_sdk import NexlaClient
except ModuleNotFoundError:  # pragma: no cover - lets unit tests patch/use __new__ without SDK installed
    NexlaClient = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def _log_sdk_response(operation: str, flow_id: int, response: Any) -> None:
    logger.info("Nexla SDK %s response for flow %s: %s", operation, flow_id, response)


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if hasattr(value, "model_dump"):
        return _plain(value.model_dump())
    if hasattr(value, "dict"):
        return _plain(value.dict())
    if hasattr(value, "__dict__"):
        return {k: _plain(v) for k, v in vars(value).items() if not k.startswith("_")}
    return value


def _resource_type_for_metrics(resource_type: str | None) -> str | None:
    if resource_type is None:
        return None
    normalized = str(resource_type).strip().lower()
    return {
        "data_source": "data_sources",
        "data_sources": "data_sources",
        "source": "data_sources",
        "data_set": "data_sets",
        "data_sets": "data_sets",
        "dataset": "data_sets",
        "data_sink": "data_sinks",
        "data_sinks": "data_sinks",
        "sink": "data_sinks",
    }.get(normalized)


def _is_flow_resource(resource_type: str | None) -> bool:
    if resource_type is None:
        return False
    return str(resource_type).strip().lower() in {"flow", "data_flow", "data_flows"}


def _first_list(value: Any, *keys: str) -> list[Any]:
    if isinstance(value, list):
        return value
    if not isinstance(value, dict):
        return []
    for key in keys:
        rows = value.get(key)
        if isinstance(rows, list):
            return rows
        if isinstance(rows, dict):
            nested = _first_list(rows, *keys)
            if nested:
                return nested
    return []


def _run_summary_rows(value: Any) -> list[dict[str, Any]] | None:
    if isinstance(value, list):
        rows = value
    elif isinstance(value, dict):
        rows = _first_list(value, "run_summary", "runSummary", "summary", "data", "items", "runs", "metrics")
        if not rows:
            rows = [row for row in value.values() if isinstance(row, dict)]
        if len(rows) == 1 and isinstance(rows[0], dict):
            nested = _run_summary_rows(rows[0])
            if nested:
                rows = nested
    else:
        rows = []
    if not rows:
        return None
    return [row for row in rows if isinstance(row, dict)]


class NexlaAdapter:
    def __init__(self, service_key: str, api_url: str | None = None) -> None:
        if NexlaClient is None:
            raise RuntimeError("nexla_sdk is required to create NexlaAdapter")
        if api_url:
            self._client = NexlaClient(service_key=service_key, base_url=api_url)
        else:
            self._client = NexlaClient(service_key=service_key)

    def smoke_test_flows_list(self) -> int:
        """Run a safe read-only auth probe using flows.list."""
        flows: Any = self._client.flows.list()
        return len(flows) if isinstance(flows, Sized) else 0

    def get_flow(self, flow_id: int) -> dict[str, Any] | None:
        value = _plain(self._client.flows.get(int(flow_id), flows_only=False))
        _log_sdk_response("flows.get", int(flow_id), value)
        return value if isinstance(value, dict) else None

    def pause_flow(self, flow_id: int) -> Any:
        value = _plain(self._client.flows.pause(int(flow_id), all=False))
        _log_sdk_response("flows.pause", int(flow_id), value)
        return value

    def activate_flow(self, flow_id: int) -> Any:
        value = _plain(self._client.flows.activate(int(flow_id), all=False))
        _log_sdk_response("flows.activate", int(flow_id), value)
        return value

    def list_unread_notifications(self, from_timestamp: int | None = None) -> list[Any]:
        """Fetch unread Nexla notifications, optionally bounded by a unix timestamp."""
        return list(self._client.notifications.list(read=0, from_timestamp=from_timestamp))

    def mark_notifications_read(self, notification_ids: list[int]) -> None:
        """Mark Nexla notifications as read after their anomalies are handled."""
        if notification_ids:
            try:
                self._client.notifications.mark_read(notification_ids)
            except Exception as exc:
                logger.debug("Failed to mark notifications read: %s", exc)

    def resolve_flow(self, resource_type: str | None, resource_id: int | None) -> int | None:
        if not resource_type or resource_id is None:
            return None
        if _is_flow_resource(resource_type):
            return int(resource_id)
        sdk_resource_type = _resource_type_for_metrics(resource_type) or resource_type
        try:
            flows = _plain(self._client.flows.get_by_resource(sdk_resource_type, resource_id, flows_only=False))
        except Exception as exc:
            logger.debug("Failed to resolve flow for %s/%s: %s", resource_type, resource_id, exc)
            return None
        candidates = _first_list(flows, "flows") or (flows if isinstance(flows, list) else [flows])
        for flow in candidates:
            if isinstance(flow, dict):
                value = flow.get("origin_node_id") or flow.get("flow_id") or flow.get("id")
                if value is not None:
                    return int(value)
        return None

    def get_flow_health(self, flow_id: int) -> dict[str, Any] | None:
        try:
            value = _plain(self._client.flows.get_flow_health(flow_id))
            rows = _first_list(value, "data", "items", "flows", "results")
            if rows:
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    row_flow_id = row.get("origin_node_id") or row.get("flow_id") or row.get("id")
                    if row_flow_id is None or int(row_flow_id) == int(flow_id):
                        return row
            return value if isinstance(value, dict) else None
        except Exception as exc:
            logger.debug("Failed to get flow health for %s: %s", flow_id, exc)
            return None

    def get_run_status(self, flow_id: int, run_id: Any) -> dict[str, Any] | None:
        try:
            value = _plain(self._client.flows.get_run_status(int(flow_id), int(run_id)))
            return value if isinstance(value, dict) else None
        except Exception as exc:
            logger.debug("Failed to get run status for %s/%s: %s", flow_id, run_id, exc)
            return None

    def get_flow_error_logs(self, flow_id: int, run_id: Any, limit: int = 5) -> list[dict[str, Any]] | None:
        try:
            run_ids = list(run_id) if isinstance(run_id, (list, tuple, set)) else [run_id]
            value = _plain(self._client.flows.search_flow_logs(flow_id, run_ids=run_ids, severity="ERROR", size=limit))
            rows = _first_list(value, "logs", "items", "data")
            return [row for row in rows[:limit] if isinstance(row, dict)]
        except Exception as exc:
            logger.debug("Failed to get flow error logs for %s/%s: %s", flow_id, run_id, exc)
            return None

    def get_run_metrics(
        self,
        flow_id: int,
        resource_type: str | None = None,
        resource_id: int | None = None,
        run_id: Any | None = None,
    ) -> dict[str, Any] | None:
        metrics_resource_type = _resource_type_for_metrics(resource_type)
        if metrics_resource_type is None or resource_id is None:
            logger.debug("Skipping run metrics for flow %s; resource type/id unavailable", flow_id)
            return None
        try:
            try:
                value = _plain(
                    self._client.metrics.get_resource_metrics_by_run(
                        metrics_resource_type, resource_id, groupby="runId", orderby="runId", size=25
                    )
                )
            except TypeError:
                value = _plain(self._client.metrics.get_resource_metrics_by_run(metrics_resource_type, resource_id, size=25))
            rows = value if isinstance(value, list) else _first_list(value, "data", "items", "runs", "metrics")
            expected_run_id = str(run_id) if run_id is not None else None
            if rows:
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    row_run_id = row.get("runId") or row.get("run_id") or row.get("runid")
                    if expected_run_id is not None and str(row_run_id) == expected_run_id:
                        return row
                logger.info(
                    "Run metrics did not include requested run resource=%s/%s requested_run=%s available_runs=%s",
                    metrics_resource_type,
                    resource_id,
                    expected_run_id,
                    [str(row.get("runId") or row.get("run_id") or row.get("runid")) for row in rows[:5] if isinstance(row, dict)],
                )
                # No row matched the requested run: return None rather than a wrong run's
                # numbers. The enricher falls back to the flow health record's
                # latestRecordCount/latestErrorCount, so counts are not lost.
                return None if expected_run_id is not None else rows[0] if isinstance(rows[0], dict) else None
            return value if isinstance(value, dict) else None
        except Exception as exc:
            logger.debug("Failed to get run metrics for %s/%s: %s", metrics_resource_type, resource_id, exc)
            return None

    def get_run_summary(
        self,
        flow_id: int,
        resource_type: str | None = None,
        resource_id: int | None = None,
        run_id: Any | None = None,
    ) -> list[dict[str, Any]] | None:
        metrics_resource_type = _resource_type_for_metrics(resource_type)
        if metrics_resource_type is None or resource_id is None:
            logger.debug("Skipping run summary for flow %s; resource type/id unavailable", flow_id)
            return None
        metrics = getattr(self._client, "metrics", None)
        if metrics is None:
            return None
        candidates = (
            "get_resource_run_summary",
            "get_resource_metrics_run_summary",
        )
        for name in candidates:
            try:
                method = getattr(metrics, name, None)
            except Exception as exc:
                logger.debug("Run summary SDK method %s unavailable: %s", name, exc)
                continue
            if not callable(method):
                continue
            try:
                value = _plain(method(metrics_resource_type, resource_id, size=25))
                return _run_summary_rows(value)
            except TypeError:
                try:
                    value = _plain(method(metrics_resource_type, resource_id))
                    return _run_summary_rows(value)
                except Exception as exc:
                    logger.debug("Failed to get run summary via %s for %s/%s: %s", name, metrics_resource_type, resource_id, exc)
            except Exception as exc:
                logger.debug("Failed to get run summary via %s for %s/%s: %s", name, metrics_resource_type, resource_id, exc)
        try:
            method = getattr(metrics, "get_resource_metrics_by_run", None)
        except Exception as exc:
            logger.debug("Run summary SDK method get_resource_metrics_by_run unavailable: %s", exc)
            method = None
        if callable(method):
            try:
                try:
                    value = _plain(method(metrics_resource_type, resource_id, groupby="runId", orderby="runId", size=25))
                except TypeError:
                    value = _plain(method(metrics_resource_type, resource_id, size=25))
                return _run_summary_rows(value)
            except Exception as exc:
                logger.debug("Failed to get run summary via get_resource_metrics_by_run for %s/%s: %s", metrics_resource_type, resource_id, exc)
        return None

    def list_unhealthy_flows(self, health_status: str = "RED") -> list[dict[str, Any]]:
        try:
            value = _plain(self._client.flows.get_org_health_flows(health_status=health_status))
            rows = _first_list(value, "data", "items", "flows", "results")
            return [row for row in rows if isinstance(row, dict)]
        except Exception as exc:
            logger.debug("Failed to list unhealthy flows: %s", exc)
            return []

    def list_flow_volumes(self, day: str) -> list[dict[str, Any]]:
        """Per-flow record volume for a single UTC date window (YYYY-MM-DD).

        Reads org health scoped to ``[day, day]``; each entry carries the flow's
        ``origin_node_id``, ``healthStatus``, and ``latestRecordCount`` for that
        window. Read-only; degrades to an empty list on any SDK error.
        """
        try:
            value = _plain(self._client.flows.get_org_health_flows(from_date=day, to_date=day))
            rows = _first_list(value, "data", "items", "flows", "results")
            return [row for row in rows if isinstance(row, dict)]
        except Exception as exc:
            logger.debug("Failed to list flow volumes for %s: %s", day, exc)
            return []
