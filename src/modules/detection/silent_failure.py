from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from modules.detection.anomaly import Anomaly
from modules.parsing import get_value, optional_int

# Default threshold: a flow is a Silent Failure when its latest run moved at least this
# percentage fewer records than the previously observed run (run-over-run via snapshots).
DEFAULT_VOLUME_THRESHOLD_PCT = 40.0
# Flows whose baseline volume is below this are too small/variable to alert on.
DEFAULT_MIN_BASELINE_RECORDS = 100


@dataclass(frozen=True)
class RunVolumeObservation:
    """A flow's current record volume versus the previous captured run/observation."""

    flow_id: int
    flow_name: str | None
    current_volume: int
    previous_volume: int | None
    status: str | None = None


RUNNING_STATUS_VALUES = {
    "ACTIVE",
    "GREEN",
    "HEALTHY",
    "OK",
    "RUNNING",
    "STARTED",
    "SUCCESS",
    "SUCCEEDED",
}


def _flow_status(row: Any) -> str | None:
    value = get_value(
        row,
        "healthStatus",
        get_value(
            row,
            "health_status",
            get_value(row, "status", get_value(row, "state", get_value(row, "flow_status"))),
        ),
    )
    return str(value).strip().upper() if value is not None and str(value).strip() else None


def _is_running_status(status: str | None) -> bool:
    """Return True only for rows that explicitly look healthy/running.

    Silent Failure means the flow appears healthy/running but moved far fewer records.
    If the org-health/current-volume row lacks a reliable health/status field, we skip
    it conservatively to avoid alerting on already RED/failed/paused/stopped flows.
    """
    return status is not None and status.strip().upper() in RUNNING_STATUS_VALUES


def _record_count(row: Any) -> int | None:
    value = get_value(
        row,
        "latestRecordCount",
        get_value(row, "latest_record_count", get_value(row, "recordCount", get_value(row, "records"))),
    )
    return optional_int(value)


def extract_flow_volumes(rows: Iterable[Any] | None) -> dict[int, tuple[str | None, int, str | None]]:
    """Parse adapter org-health rows into ``{flow_id: (flow_name, record_count, status)}``.

    Rows without a resolvable flow id are skipped; a missing/null record count is
    treated as 0 (the flow is present in the window but moved no data).
    """
    volumes: dict[int, tuple[str | None, int, str | None]] = {}
    for row in rows or []:
        flow_id = optional_int(
            get_value(
                row,
                "flow_id",
                get_value(row, "origin_node_id", get_value(row, "originNodeId", get_value(row, "id"))),
            )
        )
        if flow_id is None:
            continue
        name = get_value(row, "flow_name", get_value(row, "name"))
        count = _record_count(row)
        volumes[flow_id] = (name, count if count is not None else 0, _flow_status(row))
    return volumes


def build_run_observations(
    current: dict[int, tuple[str | None, int, str | None]],
    previous_volume: Callable[[int], int | None],
) -> list[RunVolumeObservation]:
    """Pair each flow's current latest-run volume with the previously observed one.

    ``previous_volume`` reads the most recent snapshot for the flow (a prior tick's
    latest-run count), captured before this tick upserts the current count.
    """
    return [
        RunVolumeObservation(flow_id, name, count, previous_volume(flow_id), status)
        for flow_id, (name, count, status) in current.items()
    ]


def detect_run_drop_failures(
    observations: Iterable[RunVolumeObservation],
    *,
    threshold_pct: float = DEFAULT_VOLUME_THRESHOLD_PCT,
    min_baseline: int = DEFAULT_MIN_BASELINE_RECORDS,
    per_flow_threshold: dict[int, float] | None = None,
    exclude_flow_ids: set[int] | None = None,
) -> list[Anomaly]:
    """Flag flows whose latest run moved far fewer records than the previously observed run.

    Run-over-run Silent Failure detection: the flow must still look running/healthy, have a
    meaningful previous volume (>= ``min_baseline``), and not already have an Anomaly this
    tick (``exclude_flow_ids``). The per-flow threshold overrides the global one for flows
    with high natural variance.
    """
    excluded = exclude_flow_ids or set()
    overrides = per_flow_threshold or {}
    anomalies: list[Anomaly] = []

    for obs in observations:
        if obs.flow_id in excluded:
            continue
        if not _is_running_status(obs.status):
            continue
        previous = obs.previous_volume
        if previous is None or previous <= 0 or previous < min_baseline:
            continue
        flow_threshold = float(overrides.get(obs.flow_id, threshold_pct))
        drop_pct = (previous - obs.current_volume) / previous * 100
        if drop_pct < flow_threshold:
            continue
        message = (
            f"Volume dropped {drop_pct:.0f}% versus the previous run/observation "
            f"({obs.current_volume} records now vs {previous} previously)"
        )
        anomalies.append(
            Anomaly(0, "silent_failure", obs.flow_id, obs.flow_name, "WARNING", None, "flow", message, None)
        )
    return anomalies
