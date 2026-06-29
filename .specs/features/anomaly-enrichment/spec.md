# Anomaly Enrichment

Detect Explicit Failure notifications without assuming `resource_id` is a flow id, resolve the owning flow through the Nexla adapter when possible, enrich every Anomaly with read-only Evidence, classify from that Evidence, and include the Evidence in emitted Alerts. Unresolved or partially enriched Anomalies must still alert.

Acceptance:

- Notifications keep their raw `resource_id`/`resource_type` and resolve an owning `flow_id` through the Nexla adapter when possible.
- Every Anomaly goes through Enrichment before classification; failed reads produce partial Evidence instead of dropping the Anomaly.
- The LLM payload and emitted Alert include Evidence.
- RED org-health flows with no notification produce Alerts, while flows already alerted by notification in the same tick are deduped.
- Nexla calls added by this feature are read-only.
