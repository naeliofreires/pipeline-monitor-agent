# Enrich anomalies with flow health, run status, and error logs before classifying

Before the agent asks the LLM to classify and explain an Anomaly, it first gathers the real state of the flow: its current health status, the status of the latest run, the record and error counts for that run, and the actual error log lines. This enrichment happens in code, after detection and before classification. The LLM then reasons over this evidence instead of over the notification message alone.

Until now the agent built its entire judgment from a single notification string (`message`, `level`, `resource_type`). That is flow-level triage: it can say *that* a flow is unhealthy but not *why*, and the Recommended Action is a guess. An operator who receives such an Alert still has to open Nexla and do the real diagnosis by hand — which is the exact problem the agent exists to remove.

The data points needed to make an Alert actionable already exist in the Nexla SDK and are confirmed by the Nexla docs (Data Flow Insights → Run Execution Logs, which expose per-run *processed records*, *errors*, *size*, and error detail):

- `flows.get_flow_health(flow_id)` — `healthStatus` (GREEN/YELLOW/RED), `latestErrorCount`, `latestRecordCount`, `latestRunId`, `errorSummary`
- `flows.get_run_status(flow_id, run_id)` — the latest run's lifecycle status
- `flows.search_flow_logs(flow_id, severity="ERROR", run_id=...)` — the actual error log lines
- `metrics.get_resource_metrics_by_run(...)` — per-run `records` / `errors` / `size`

This does not change the principle in [ADR-0002](0002-deterministic-detection-llm-classification.md): detection stays deterministic code, and the LLM is still called only after a problem is found. Enrichment is also deterministic code; it sits between detection and classification and only adds evidence to the payload the LLM already receives.

**Consequence**: each anomaly now triggers a small number of extra read-only Nexla API calls (health, run status, error logs) before the single LLM call. This costs latency and adds rate-limit pressure per anomaly — acceptable because the LLM is still only called once per real problem, not per cycle. If any enrichment call fails, the agent degrades gracefully to the message-only payload and still produces an Alert; an Anomaly is never dropped because enrichment failed. Enrichment also depends on resolving a notification's `resource_id`/`resource_type` to the owning flow, because the health/logs/run-status endpoints key off the flow's id, not the data source/set/sink that raised the notification.

**Considered Options**: (1) *Send the notification message only and let the LLM infer the rest* — rejected; the model cannot invent error counts or run status it was never shown, so the Recommended Action stays a guess. (2) *Pre-fetch health and logs for every flow each cycle and pass it all to the LLM* — rejected for the same cost/scale reasons as ADR-0002; we only enrich flows that detection has already flagged. (3) *Enrich inside the classifier* — rejected; the classifier is business logic that must not call external services. Enrichment that talks to the Nexla SDK belongs in the adapter layer, orchestrated by a dedicated enrichment module.
