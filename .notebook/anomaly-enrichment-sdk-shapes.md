# Anomaly enrichment Nexla SDK shapes

Tags: enrichment, nexla-sdk, anomaly

## Pointers

- Flow resolution: `src/adapters/nexla_adapter.py:resolve_flow()` must handle SDK `FlowResponse` data under `flows`; the owning flow id is `origin_node_id` when present.
- Notification resources: `data_source`, `data_set`, and `data_sink` need normalization to SDK metric/resource paths `data_sources`, `data_sets`, and `data_sinks`.
- Run metrics: `metrics.get_resource_metrics_by_run(...)` returns nested metrics data; enrichment must select the row matching the latest run id instead of taking the first row.
- Log failures: adapter returns `None` on SDK failure so `src/modules/enrichment/enricher.py:enrich_anomaly()` can set `Evidence.partial=True`; an empty list means the call succeeded but no logs were returned.
