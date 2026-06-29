from __future__ import annotations

from datetime import datetime

from modules.classification.classifier import ClassificationResult
from modules.detection.anomaly import Anomaly
from modules.enrichment.enricher import Evidence
from modules.redaction import redact

_RISK_ICON = {"high": "🔴", "low": "🟡", "unknown": "⚪"}
_TYPE_LABEL = {
    "explicit_failure": "Explicit Failure",
    "health_sweep": "Health Sweep",
    "silent_failure": "Silent Failure",
}
_SEPARATOR = "━" * 60


def _type_label(anomaly_type: str) -> str:
    return _TYPE_LABEL.get(anomaly_type, anomaly_type.replace("_", " ").title())


def _detected_at(anomaly: Anomaly) -> str:
    if isinstance(anomaly.detected_at, datetime):
        return anomaly.detected_at.isoformat()
    return anomaly.detected_at or "unknown time"


def _counts(evidence: Evidence) -> str:
    records = evidence.records_this_run if evidence.records_this_run is not None else "?"
    errors = evidence.errors_this_run if evidence.errors_this_run is not None else "?"
    return f"{records}/{errors}"


def build_anomaly_alert_text(
    anomaly: Anomaly, evidence: Evidence, classification: ClassificationResult
) -> str:
    """Build console output for an Anomaly."""
    icon = _RISK_ICON.get(classification.risk_classification, "⚪")
    flow = anomaly.flow_name or anomaly.flow_id or "unknown flow"
    risk = classification.risk_classification.upper()

    lines = [
        f'{icon} [{risk}] Flow "{flow}" — {_type_label(anomaly.type)}',
        _SEPARATOR,
    ]

    # Evidence — the grounding the agent adds beyond the raw notification.
    run = evidence.latest_run_id if evidence.latest_run_id is not None else "unknown"
    lines.append(
        " | ".join(
            [
                f"Health: {evidence.health_status or 'unknown'}",
                f"Run {run}: {evidence.run_status or 'unknown'}",
                f"Records/Errors: {_counts(evidence)}",
            ]
        )
    )
    if evidence.error_summary:
        lines.append(f"Error Summary: {redact(evidence.error_summary)}")
    if evidence.top_error_logs:
        lines.append(f"Top Error: {redact(evidence.top_error_logs[0])}")
    if anomaly.message:
        lines.append(f"Message: {redact(anomaly.message)}")
    if evidence.partial:
        lines.append("⚠ Evidence is partial — some flow data could not be read.")

    lines += [
        "",
        f"Explanation: {classification.explanation}",
        f"Recommended Action: {classification.recommended_action}",
        "",
        f"Flow ID: {anomaly.flow_id or 'unknown'} | Detected: {_detected_at(anomaly)}"
        + (f" | Notification {anomaly.notification_id}" if anomaly.notification_id else ""),
    ]
    return "\n".join(lines)
