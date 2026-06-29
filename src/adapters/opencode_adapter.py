from __future__ import annotations

import json
import os
from typing import Any


NEXLA_ANOMALY_ANALYSIS_PROMPT = """Classify this Nexla Anomaly using only the supplied Evidence.

Product context:
- Nexla moves data through Flows. A Flow is the monitored execution path made of a source, transform step, and destination.
- The monitoring agent is read-only. It watches Flows, explains Anomalies, and recommends what an operator should inspect or do next; it must never imply it already changed Nexla state.
- An Explicit Failure is an Anomaly Nexla reported through a notification.
- A Silent Failure is an Anomaly detected from volume behavior: the Flow is still running but processed much fewer records than expected, and Nexla did not report it directly.
- Enrichment may include flow health, latest run status, record/error counts, an error summary, and top error log lines. Treat these as Evidence, not as guaranteed complete truth.
- For Capsule-like Flows, source, transform, and destination behavior should be considered part of one Flow-level execution path. Avoid recommending isolated node changes unless Evidence points to the specific resource.

Risk Classification rules:
- Return `high` when Evidence shows failed/errored run status, RED/unhealthy flow health, authentication or authorization failures, destination rejections, connector/source access failures, schema/format errors, zero records with errors, or a Silent Failure that could indicate stalled ingestion or delivery.
- Return `low` only when Evidence shows the Flow is healthy/running, records are moving, errors are absent or clearly transient, and the operator can safely monitor.
- Return `uncertain` when critical Evidence is missing, partial, contradictory, or the Anomaly cannot be tied to a Flow/run/resource. Partial Evidence should be called out explicitly.

Response rules:
- Cite concrete Evidence when present: notification message, resource type/id, flow id/name, health status, run id/status, record/error counts, error summary, and specific top error log lines.
- If Evidence is partial, say exactly what is missing or inconclusive.
- Keep explanation plain-language and operator-facing.
- Make recommended_action specific, read-only, and safe: inspect the named Flow/run/resource, check credentials or permissions, review source/destination availability, examine rejected records/logs, validate schema/format changes, or rerun/activate manually only when Evidence supports it.
- Do not invent Nexla APIs, IDs, counts, owners, root causes, or remediation steps not supported by Evidence.
- Return only JSON with string keys: risk_classification (`low`, `high`, or `uncertain`), explanation, and recommended_action.
"""


class OpencodeAdapter:
    """Adapter for opencode.ai Zen anomaly classification calls."""

    def __init__(
        self,
        model: str = "big-pickle",
        api_key: str | None = None,
        base_url: str = "https://opencode.ai/zen/v1",
        client: Any | None = None,
    ) -> None:
        self.model = model
        if client is not None:
            self.client = client
            return

        from openai import OpenAI

        self.client = OpenAI(api_key=api_key or os.getenv("OPENCODE_API_KEY"), base_url=base_url)

    def classify_anomaly(self, payload: dict[str, Any]) -> dict[str, Any]:
        prompt = f"{NEXLA_ANOMALY_ANALYSIS_PROMPT}\nAnomaly: {json.dumps(payload, default=str)}"
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
        )
        text = response.choices[0].message.content
        if not text:
            raise ValueError("opencode.ai Zen response had empty content")
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("opencode.ai Zen response JSON was not an object")
        return parsed
