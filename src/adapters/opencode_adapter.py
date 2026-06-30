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
- Enrichment may include flow health, latest run status, record/error counts, recent run-summary trends, an error summary, a recent_run_log_check result, and top error log lines. Treat these as Evidence, not as guaranteed complete truth.
- For Capsule-like Flows, source, transform, and destination behavior should be considered part of one Flow-level execution path. Avoid recommending isolated node changes unless Evidence points to the specific resource.

Risk Classification rules:
- Return `high` when Evidence shows failed/errored run status, RED/unhealthy flow health, authentication or authorization failures, destination rejections, connector/source access failures, schema/format errors, zero records with errors, or a Silent Failure that could indicate stalled ingestion or delivery.
- Return `low` only when Evidence shows the Flow is healthy/running, records are moving, errors are absent or clearly transient, and the operator can safely monitor.
- Return `uncertain` when critical Evidence is missing, partial, contradictory, or the Anomaly cannot be tied to a Flow/run/resource. Partial Evidence should be called out explicitly.

Response rules:
- Cite concrete Evidence when present: notification message, resource type/id, flow id/name, health status, run id/status, record/error counts, recent run-summary trends, error summary, and specific top error log lines.
- The explanation must explicitly state that the agent checked logs from the latest/recent runs of the Flow being analyzed looking for Anomalies. If top_error_logs are present or recent_run_log_check says anomalies_found, summarize what was found in those Nexla ERROR logs. If recent_run_log_check says none_found, state that no ERROR log Anomalies were found. If Evidence is partial or recent_run_log_check is inconclusive/missing, state that the log check was inconclusive and do not imply all historical logs were checked.
- If Evidence is partial, say exactly what is missing or inconclusive.
- Keep explanation plain-language and operator-facing.
- Make recommended_action specific, read-only, and safe: inspect the named Flow/run/resource, check credentials or permissions, review source/destination availability, examine rejected records/logs, validate schema/format changes, or rerun/activate manually only when Evidence supports it.
- Do not invent Nexla APIs, IDs, counts, owners, root causes, or remediation steps not supported by Evidence.
- Return only JSON with string keys: risk_classification (`low`, `high`, or `uncertain`), explanation, and recommended_action.
"""


NEXLA_COMMAND_ROUTER_PROMPT = """You route an operator's request to one tool for a read-only Nexla pipeline-monitoring agent.
- Pick exactly one tool when the request maps to one; do not chain tools.
- If the request is a greeting, is unclear, or asks what you can do, answer briefly in one or two sentences instead of calling a tool.
- Never invent a flow ID; only pass an ID the operator actually gave.
- You cannot pause, activate, or otherwise change flows — those require human confirmation and are not available to you.
"""


def _route_response_to_dict(message: Any) -> dict[str, Any]:
    """Map a chat-completion message to {"tool", "arguments"} or {"text"}."""
    tool_calls = getattr(message, "tool_calls", None)
    if tool_calls:
        call = tool_calls[0]
        try:
            arguments = json.loads(call.function.arguments or "{}")
        except (TypeError, ValueError):
            arguments = {}
        return {"tool": call.function.name, "arguments": arguments if isinstance(arguments, dict) else {}}
    content = (getattr(message, "content", None) or "").strip()
    return {"text": content}


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

    def route_command(self, message: str, tools: list[dict[str, Any]]) -> dict[str, Any]:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": NEXLA_COMMAND_ROUTER_PROMPT},
                {"role": "user", "content": message},
            ],
            tools=tools,
            tool_choice="auto",
            max_tokens=300,
        )
        return _route_response_to_dict(response.choices[0].message)
