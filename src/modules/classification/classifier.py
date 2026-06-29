from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol

from modules.detection.anomaly import Anomaly
from modules.enrichment.enricher import Evidence
from modules.redaction import redact

logger = logging.getLogger(__name__)

SAFE_RECOMMENDED_ACTION = "Review the Nexla notification and flow run details before taking action."
VALID_RISKS = {"low", "high"}


class AnomalyClassifier(Protocol):
    """An LLM adapter that classifies an anomaly payload and returns a JSON-like mapping."""

    def classify_anomaly(self, payload: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class ClassificationResult:
    risk_classification: str
    explanation: str
    recommended_action: str


def _fallback(anomaly: Anomaly) -> ClassificationResult:
    return ClassificationResult(
        risk_classification="unknown",
        explanation=str(redact(anomaly.message)),
        recommended_action=SAFE_RECOMMENDED_ACTION,
    )


def _payload(anomaly: Anomaly, evidence: Evidence) -> dict[str, Any]:
    return {
        "type": anomaly.type,
        "notification_id": anomaly.notification_id,
        "flow_id": anomaly.flow_id,
        "flow_name": anomaly.flow_name,
        "level": anomaly.level,
        "resource_id": anomaly.resource_id,
        "resource_type": anomaly.resource_type,
        "message": redact(anomaly.message),
        "detected_at": str(anomaly.detected_at),
        "evidence": {
            "health_status": evidence.health_status,
            "run_status": evidence.run_status,
            "latest_run_id": evidence.latest_run_id,
            "records_this_run": evidence.records_this_run,
            "errors_this_run": evidence.errors_this_run,
            "error_summary": redact(evidence.error_summary),
            "top_error_logs": [redact(log) for log in evidence.top_error_logs],
            "partial": evidence.partial,
        },
    }


def classify_anomaly(anomaly: Anomaly, evidence: Evidence, llm_adapter: AnomalyClassifier) -> ClassificationResult:
    """Classify an anomaly with an LLM adapter, falling back safely on errors."""
    try:
        response = llm_adapter.classify_anomaly(_payload(anomaly, evidence))
    except Exception:
        logger.warning(
            "LLM classification failed for notification %s; using fallback",
            anomaly.notification_id,
            exc_info=True,
        )
        return _fallback(anomaly)

    if not isinstance(response, dict):
        logger.warning(
            "LLM returned a non-mapping response for notification %s; using fallback",
            anomaly.notification_id,
        )
        return _fallback(anomaly)

    risk = response.get("risk_classification")
    explanation = response.get("explanation")
    action = response.get("recommended_action")

    if not isinstance(risk, str) or not isinstance(explanation, str) or not isinstance(action, str):
        logger.warning(
            "LLM response missing expected string fields for notification %s; using fallback",
            anomaly.notification_id,
        )
        return _fallback(anomaly)

    normalized_risk = risk.strip().lower()
    if normalized_risk == "uncertain":
        normalized_risk = "high"
    if normalized_risk not in VALID_RISKS:
        logger.warning(
            "LLM returned unrecognized risk %r for notification %s; using fallback",
            risk,
            anomaly.notification_id,
        )
        return _fallback(anomaly)
    if not explanation.strip() or not action.strip():
        logger.warning(
            "LLM returned empty explanation/action for notification %s; using fallback",
            anomaly.notification_id,
        )
        return _fallback(anomaly)

    return ClassificationResult(normalized_risk, explanation.strip(), action.strip())
