# Silent Failure Detection (volume drop)

Detect flows that still look healthy but processed far fewer records than usual — the quiet failures that no notification and no RED health status will catch. Each tick the agent compares every flow's record volume for today's UTC date window against the same flow's volume yesterday, and raises a `silent_failure` Anomaly when the drop meets a threshold. The Anomaly then flows through the existing enrich → classify → alert → suppress pipeline. This completes Level 3 (proactive detection). See [ADR-0005](../../../docs/adr/0005-silent-failure-volume-detection.md).

Detection stays deterministic (code does the volume math); the LLM is still only called afterward to classify severity and explain. The agent never acts on a flow.

Acceptance:

- A new `modules/detection/silent_failure.py` flags a flow as a Silent Failure when `(baseline - current) / baseline` is at least `detection.volume_threshold_pct` (default 40%), where the baseline is the same flow's volume in the same window yesterday.
- A new `adapters/nexla_adapter.py::list_flow_volumes(day)` reads per-flow record volume for a single UTC date window via `flows.get_org_health_flows(from_date=day, to_date=day)`, degrading to an empty list on any SDK error.
- A new `repositories/snapshot_repository.py` persists one `(flow_id, window_start, record_count, captured_at)` row per flow per day (upserted), and answers `get_record_count(flow_id, window_start)` as the durable baseline fallback when yesterday's window cannot be re-read.
- Flows whose baseline is below `detection.min_baseline_records` (default 100) are never flagged; the threshold is overridable per flow via `detection.flows[].volume_threshold_pct`.
- A flow already reported this tick as an Explicit Failure or `health_sweep` is excluded from Silent Failure detection.
- Repeat Silent Failure alerts for the same flow are suppressed for the Suppression Window via the existing `(flow_id, 'silent_failure')` key; the whole sweep is wrapped so a read failure never blocks Explicit Failure or health-sweep alerting.
