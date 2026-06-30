# Anomaly enrichment Nexla SDK shapes

Tags: enrichment, nexla-sdk, anomaly

## Pointers

- Flow resolution: `src/adapters/nexla_adapter.py:resolve_flow()` must handle SDK `FlowResponse` data under `flows`; the owning flow id is `origin_node_id` when present.
- Notification resources: `data_source`, `data_set`, and `data_sink` need normalization to SDK metric/resource paths `data_sources`, `data_sets`, and `data_sinks`.
- Run metrics: `metrics.get_resource_metrics_by_run(...)` returns nested metrics data; enrichment must select the row matching the latest run id instead of taking the first row.
- Run summary: `/data_sources/{source_id}/metrics/run_summary` and `/data_sinks/{destination_id}/metrics/run_summary` attribute runs by the resource in the request path, not by a resource id field in each row. Enrichment keeps this optional and derives compact historical Evidence in `src/modules/enrichment/enricher.py:_historical_summary()`.
- Recent run log check: when run-summary rows provide recent run ids, `src/modules/enrichment/enricher.py:enrich_anomaly()` passes those ids to `NexlaAdapter.get_flow_error_logs()` so the LLM can state whether latest/recent Flow run logs had Nexla ERROR log Anomalies, none were found, or the check was inconclusive.
- Log failures: adapter returns `None` on SDK failure so `src/modules/enrichment/enricher.py:enrich_anomaly()` can set `Evidence.partial=True`; an empty list means the call succeeded but no logs were returned.
