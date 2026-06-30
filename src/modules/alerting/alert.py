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
    "flow_scan": "Targeted Flow Scan",
}
_UNKNOWN = "unknown"


def _type_label(anomaly_type: str) -> str:
    return _TYPE_LABEL.get(anomaly_type, anomaly_type.replace("_", " ").title())


def _detected_at(anomaly: Anomaly) -> str:
    if isinstance(anomaly.detected_at, datetime):
        return anomaly.detected_at.isoformat()
    return anomaly.detected_at or "unknown time"


def _latest_run(evidence: Evidence) -> str:
    run = evidence.latest_run_id if evidence.latest_run_id is not None else _UNKNOWN
    status = evidence.run_status or _UNKNOWN
    return f"{run} ({status})"


def _logs_status(evidence: Evidence) -> str:
    if evidence.error_summary or evidence.top_error_logs:
        return "Available"
    if evidence.partial:
        return "Inconclusive (read failed)"
    errors = evidence.errors_this_run if evidence.errors_this_run is not None else "?"
    return f"No error log lines found; errors={errors}"


def _risk_reason(anomaly: Anomaly, evidence: Evidence) -> str:
    if evidence.partial:
        return "Incomplete Evidence"
    return _type_label(anomaly.type)


def _format_scan_table(anomaly: Anomaly, evidence: Evidence) -> list[str]:
    rows = [
        f"Health     : {evidence.health_status or _UNKNOWN}",
        f"Status     : {evidence.flow_status or _UNKNOWN}",
        f"Latest Run : {_latest_run(evidence)}",
        f"Records    : {evidence.records_this_run if evidence.records_this_run is not None else '?'}",
        f"Errors     : {evidence.errors_this_run if evidence.errors_this_run is not None else '?'}",
        f"Logs       : {_logs_status(evidence)}",
        f"Anomaly    : {_type_label(anomaly.type)}",
    ]
    if evidence.record_drop_pct is not None:
        rows.append(f"Drop       : {evidence.record_drop_pct}% below baseline")
    return rows


def _format_resource(anomaly: Anomaly) -> str:
    resource_type = anomaly.resource_type or "unknown type"
    resource_id = anomaly.resource_id if anomaly.resource_id is not None else "unknown id"
    return f"{resource_type} {resource_id}"


def _format_owner(anomaly: Anomaly) -> str:
    if anomaly.owner_name and anomaly.owner_email:
        return f"{anomaly.owner_name} <{anomaly.owner_email}>"
    return anomaly.owner_name or anomaly.owner_email or "unknown"


def _format_roles(anomaly: Anomaly) -> str:
    return ", ".join(anomaly.access_roles) if anomaly.access_roles else "unknown"


def build_anomaly_alert_text(
    anomaly: Anomaly, evidence: Evidence, classification: ClassificationResult
) -> str:
    """Build Alert text in a Slack-friendly system card style."""
    icon = _RISK_ICON.get(classification.risk_classification, "⚪")
    flow = anomaly.flow_name or anomaly.flow_id or "unknown flow"
    flow_id = anomaly.flow_id or "unknown"
    risk = classification.risk_classification.upper()

    lines = [
        f"*🚦 Flow Health Status | ID: {flow_id} [{risk}]*",
        f"*Flow:* {flow}",
        f"*Risk Level:* {icon} {risk} ({_risk_reason(anomaly, evidence)})",
        "",
    ]

    if anomaly.type == "explicit_failure":
        lines += [
            "Notification Evidence:",
            "```",
            f"Notification: {anomaly.notification_id or 'unknown'} | Level: {anomaly.level or 'unknown'} | Created: {_detected_at(anomaly)}",
            f"Resource: {_format_resource(anomaly)} | Owner: {_format_owner(anomaly)}",
            f"Org: {anomaly.org_name or 'unknown'} | Access Roles: {_format_roles(anomaly)}",
        ]
        if anomaly.read_at or anomaly.updated_at:
            lines.append(
                f"Read: {anomaly.read_at or 'unread'} | Updated: {anomaly.updated_at or 'unknown'}"
            )
        lines += ["```", ""]

    lines += ["*Scan Result:*", "```", *_format_scan_table(anomaly, evidence), "```"]
    if evidence.error_summary:
        lines.append(f"Error Summary: {redact(evidence.error_summary)}")
    if evidence.top_error_logs:
        lines.append(f"Top Error: {redact(evidence.top_error_logs[0])}")
    if anomaly.message:
        lines.append(f"Message: {redact(anomaly.message)}")
    if evidence.partial:
        lines.append("⚠ Evidence is partial: some flow data could not be read.")

    lines += [
        "",
        f"*Explanation:* {classification.explanation}",
        "",
        "*Next Steps:*",
        f"🔹 {classification.recommended_action}",
        "",
        f"Flow ID: {anomaly.flow_id or 'unknown'} | Detected: {_detected_at(anomaly)}"
        + (f" | Notification {anomaly.notification_id}" if anomaly.notification_id else ""),
    ]
    return "\n".join(lines)
