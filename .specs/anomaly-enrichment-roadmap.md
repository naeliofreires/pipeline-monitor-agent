# Anomaly Enrichment Roadmap

| Field        | Value                                                        |
| ------------ | ----------------------------------------------------------- |
| Author       | @naelio.freires                                             |
| Status       | Planned                                                     |
| Created      | 2026-06-26                                                  |
| Drives       | [ADR-0003](../docs/adr/0003-enrich-anomalies-before-classification.md) |
| Glossary     | [CONTEXT.md](../CONTEXT.md)                                  |
| Supersedes   | "metrics alone" flow-level triage                           |

## Why this roadmap exists

Today the agent builds its entire judgment of an Anomaly from a single Nexla
notification string. The detector copies only `message`, `level`,
`resource_type`, and `flow_id` (`src/modules/detection/explicit_failure.py:53`),
the classifier forwards just those fields (`src/modules/classification/classifier.py:36`),
and the LLM adapter sends only that payload (`src/adapters/opencode_adapter.py:28`).

That is **flow-level triage**: the agent can say a flow is unhealthy but not why,
so the Recommended Action is a guess and the operator still has to open Nexla and
diagnose by hand. The fix is an **Enrichment** step that pulls the real state of
the flow — health status, run status, record/error counts, and actual error log
lines — before the LLM is asked to classify. This is the decision recorded in
[ADR-0003](../docs/adr/0003-enrich-anomalies-before-classification.md).

All of these data points already exist in the Nexla SDK and are confirmed by the
Nexla docs (Data Flow Insights → Run Execution Logs: per-run *processed records*,
*errors*, *size*, and error detail). Nothing new is needed from Nexla.

## Project rules these plans follow

From `docs/tdd.md` and the existing code:

- **Modules** — business logic only (detection, enrichment orchestration,
  classification, alert building). Modules never call an external service directly.
- **Adapters** — the only place that talks to an external service (Nexla SDK,
  opencode.ai Zen). One adapter per service.
- **Repositories** — the only place that touches SQLite. (Not needed for this
  roadmap; enrichment is stateless. Reserved for the separate v1 suppression work.)
- **Detection stays deterministic; the LLM is called once, after a problem is
  found** ([ADR-0002](../docs/adr/0002-deterministic-detection-llm-classification.md)).
- **The agent never acts on a flow** ([ADR-0001](../docs/adr/0001-read-only-agent.md)).
  Every new SDK call below is read-only.
- **Never drop an Anomaly.** As with the existing classifier fallback
  (`classifier.py:53`), if enrichment fails the agent degrades to the
  message-only payload and still prints an Alert.

## Glossary additions (update `CONTEXT.md`)

- **Enrichment**: the read-only step that gathers a flow's health, latest run
  status, record/error counts, and error log lines after an Anomaly is detected
  and before it is classified. _Avoid_: hydration, lookup, fetch.
- **Evidence**: the enriched data points attached to an Anomaly and sent to the
  LLM. _Avoid_: context (overloaded), details.

---

## Sequencing

```
WI-1 (flow resolution)  ──►  WI-2 (adapter reads)  ──►  WI-3 (enrich module)  ──►  WI-4 (LLM contract)
                                     │
                                     └──►  WI-5 (org health sweep)  [parallel after WI-2]
WI-0 (docs/glossary) runs alongside; WI-6 (tests/validation) closes each item.
```

WI-1 unblocks everything: without correct `flow_id` resolution, every enrichment
read hits the wrong id. WI-5 only needs the adapter (WI-2) and is independent of
the enrichment payload path, so it can run in parallel.

---

## WI-1 — Resolve a notification to its owning flow

**Why.** A notification carries `resource_id` + `resource_type`, and that
resource can be a `data_source`, `data_set`, or `data_sink`
(`.venv/.../nexla_sdk/models/notifications/responses.py:18-19`) — **not** the
flow. But `detect_explicit_failures` casts `resource_id` straight into `flow_id`
(`src/modules/detection/explicit_failure.py:57`). The health, run-status, and
logs endpoints all key off the flow's id (`origin_node_id`), so without
resolution every enrichment call in WI-2/WI-3 targets the wrong id or 404s. This
is the prerequisite bug.

**How.**
- Adapter (`src/adapters/nexla_adapter.py`): add
  `resolve_flow(resource_type, resource_id) -> int | None` using the SDK's
  `flows.get_by_resource(...)`. Read-only.
- Detection (`src/modules/detection/explicit_failure.py`): stop assuming
  `resource_id == flow_id`. Keep the raw `resource_id`/`resource_type` on the
  `Anomaly` and resolve to `flow_id` via the adapter. Keep `Anomaly` a frozen
  dataclass; add `resource_id` and rename the existing misused field so the flow
  id is only set once resolved.
- If resolution returns `None`, keep the Anomaly with `flow_id = None`;
  enrichment (WI-3) will skip flow-keyed reads and fall back. Never drop it.

**Acceptance.**
- A notification whose `resource_type` is `data_sink` resolves to the parent
  flow id, not the sink id.
- A notification that cannot be resolved still produces an Anomaly and an Alert.
- No flow action method is called.

---

## WI-2 — Add read-only enrichment methods to the Nexla adapter

**Why.** The adapter is the only layer allowed to call the Nexla SDK. The
enrichment module (WI-3) needs four read-only reads that do not exist on the
adapter yet. Centralizing them here keeps the SDK out of the business logic.

**How.** Add to `src/adapters/nexla_adapter.py`, each wrapping one SDK call and
returning plain dicts/values (not raw SDK models), each read-only:
- `get_flow_health(flow_id)` → `flows.get_flow_health(flow_id)`
  (`healthStatus`, `latestErrorCount`, `latestRecordCount`, `latestRunId`,
  `errorSummary`).
- `get_run_status(flow_id, run_id)` → `flows.get_run_status(flow_id, run_id)`.
- `get_flow_error_logs(flow_id, run_id, limit)` → `flows.search_flow_logs(flow_id,
  severity="ERROR", run_ids=[run_id], size=limit)`; `run_id` may be a single id or
  a small list of latest/recent run ids. Return only the top `limit` `FlowLogEntry`
  lines (`level`, `message`, `timestamp`).
- `get_run_metrics(flow_id)` → `metrics.get_resource_metrics_by_run(...)` for the
  latest run (`records`, `errors`, `size`).
- `get_run_summary(flow_id, resource_type, resource_id, run_id)` → the source/sink
  `/metrics/run_summary` shape when available. Treat it as optional historical
  Evidence and attribute returned runs to the resource used for the call.
- Each method catches SDK/transport errors and returns `None` (or `[]` for logs)
  so the caller can degrade. Log failures at `DEBUG` (error messages may contain
  table/connection names — see TDD Security).

**Acceptance.**
- Each method returns a normalized dict / list / `None`; never raises to the caller.
- Mark-read and classify paths are unchanged.
- No flow action method is called.

---

## WI-3 — The Enrichment module

**Why.** Enrichment is orchestration of several reads plus shaping the Evidence
payload — business logic, so it lives in a module, not the adapter and not the
classifier ([ADR-0003](../docs/adr/0003-enrich-anomalies-before-classification.md)).
This is the heart of moving beyond flow-level metrics.

**How.**
- New module `src/modules/enrichment/enricher.py` exposing
  `enrich_anomaly(anomaly, nexla_adapter) -> Evidence`.
- `Evidence` is a frozen dataclass: `health_status`, `run_status`, `latest_run_id`,
  `records_this_run`, `errors_this_run`, `error_summary`, `top_error_logs`
  (list of short strings), compact run-summary trend fields
  (`recent_run_count`, `avg_records_previous_runs`, `latest_records_from_summary`,
  `record_drop_pct`, `latest_errors_from_summary`, `consecutive_failed_runs`),
  `recent_run_log_check`, and a `partial: bool` flag set when required reads failed.
- Flow: if `anomaly.flow_id` is `None` → return empty Evidence with
  `partial=True`. Otherwise call `get_flow_health` to learn `latestRunId`, then
  `get_run_status`, `get_run_metrics`, optional `get_run_summary`, and
  `get_flow_error_logs` (capped, e.g. top 5). If run-summary rows provide recent
  run ids, pass those ids to the log lookup so the log check covers latest/recent
  Flow runs instead of only the latest run. Any required `None` result leaves that
  field empty and sets `partial`; optional run-summary failure does not by itself
  make Evidence partial.
- The module does **not** import the SDK; it only uses the injected adapter
  (`AnomalyEnricher` Protocol, mirroring the `AnomalyClassifier` Protocol pattern
  in `classifier.py:15`).
- Wire it into `monitor_once` (`src/monitor.py:47`) between detection and
  classification: `for anomaly: evidence = enrich_anomaly(...); classification =
  classify_anomaly(anomaly, evidence, llm)`.

**Acceptance.**
- With all reads succeeding, Evidence carries health, run status, counts,
  run-summary trends when available, error log lines, and whether the latest/recent
  run log check found Anomalies, found none, or was inconclusive.
- With any read failing, `partial=True` and the loop still classifies and prints.
- Enrichment is pure orchestration — no `import nexla_sdk` in the module.

---

## WI-4 — Make the LLM classify over Evidence

**Why.** Enrichment is worthless if the LLM never sees it. The payload and prompt
must carry the Evidence so the Risk Classification and especially the Recommended
Action are grounded in observed state, not a headline.

**How.**
- `src/modules/classification/classifier.py`: change `classify_anomaly(anomaly,
  llm_adapter)` to `classify_anomaly(anomaly, evidence, llm_adapter)` and extend
  `_payload(...)` to include the Evidence fields. Fallback behavior is unchanged
  (invalid/failed LLM → `unknown` + raw message + safe action).
- `src/adapters/opencode_adapter.py`: update the prompt to instruct the model to
  cite the specific errors / run status / counts in `explanation`, and to base
  `recommended_action` on them. Keep the strict JSON output contract
  (`risk_classification`, `explanation`, `recommended_action`).
  The explanation must explicitly mention the latest/recent Flow run log check:
  summarize Nexla ERROR log Anomalies when present, say no ERROR log Anomalies were
  found when the check succeeded with no rows, or say the check was inconclusive
  when Evidence is partial/missing.
- `src/modules/alerting/alert.py`: add an Evidence block to the Alert text
  (health status, run status, records/errors this run, and the top error line) so
  the operator sees the evidence even when the LLM is in fallback.

**Acceptance.**
- The payload sent to the LLM contains health status, run status, counts,
  run-summary trends, the recent run log-check result, and error log lines when
  present.
- A `partial` Evidence still classifies (the LLM is told which fields are missing).
- The Alert shows the Evidence block; `uncertain → high` and the `unknown`
  fallback still hold.

---

## WI-5 — Org health sweep (early Silent-Failure coverage)

**Why.** `flows.get_org_health_flows(health_status="RED")` returns every
unhealthy flow with `errorSummary` and `latestErrorCount` **without needing a
notification**. This delivers two TDD goals early: a single place to see the
health of all flows (`docs/tdd.md:19`), and catching problems Nexla did not send
a notification for — a cheap first slice of Silent Failure detection, ahead of
the full volume-comparison work.

**How.**
- Adapter: add `list_unhealthy_flows(health_status="RED") ->
  list[dict]` wrapping `flows.get_org_health_flows(...)`. Read-only.
- Detection: new `src/modules/detection/health_sweep.py` →
  `detect_unhealthy_flows(health_entries) -> list[Anomaly]` with
  `type="health_sweep"`, deduping against flows already alerted this tick from
  the notification path (by `flow_id`).
- These Anomalies flow through the same Enrichment → Classification → Alert path.
- Out of scope here: the 40%-volume Silent Failure rule, Suppression Window, and
  SQLite state (separate v1 work in the TDD). WI-5 deliberately reuses Nexla's own
  health verdict instead of computing volume deltas.

**Acceptance.**
- A RED flow with no notification still produces an Alert.
- A flow already alerted via the notification path this tick is not double-alerted.
- No flow action method is called.

---

## WI-0 / WI-6 — Docs and verification (run alongside)

**WI-0 — Docs.** Add the *Enrichment* and *Evidence* terms to `CONTEXT.md`; update
`docs/tdd.md` Data Flow and architecture diagram to show the enrichment step and
the org-health source; mark ADR-0003 in the TDD header.

**WI-6 — Tests & validation.** Mirror the existing convention
(`tests/test_explicit_failure_alert.py` + `.specs/features/<name>/validation.md`):
- Unit: flow resolution (source/set/sink → flow id), enricher happy path and
  partial-failure path, classifier with Evidence, health-sweep dedup.
- Integration: `monitor_once` with a mocked Nexla adapter — full path
  detect → resolve → enrich → classify → alert → mark-read, plus a
  `ForbiddenFlows` sentinel proving no flow action is ever called.
- Each work item gets a one-paragraph `spec.md` and an evidence-based
  `validation.md` under `.specs/features/`, matching `explicit-failure-alert`.
- Gates: `PYTHONPATH=src python -m unittest discover -s tests` and
  `PYTHONPATH=src python -m compileall src tests` must pass.

---

## What level the agent reaches after this roadmap

Maturity scale for a monitoring agent:

| Level | Name | What it does |
| ----- | ---- | ------------ |
| 0 | Manual | Operator checks flows by hand. |
| 1 | **Reactive relay** | Forwards Nexla notifications, adds an LLM headline. *(where the agent is today)* |
| 2 | **Evidence-grounded triage** | Correlates health + run status + error logs + counts; classifies and recommends from observed state. |
| 3 | Proactive detection | Finds problems with no notification (silent failures, fleet sweep) + state/suppression to control noise. |
| 4 | Supervised action | Operator-approved remediation. |
| 5 | Autonomous remediation | Acts on its own within guardrails. |

**Today: Level 1.** The agent only relays notifications and labels them from a
single string.

**After this roadmap: a solid Level 2, with a foot in Level 3.**
- WI-1 → WI-4 move it fully to **Level 2**: every Alert is grounded in real
  errors, run status, and record/error counts, so the Risk Classification is
  defensible and the Recommended Action is specific enough to act on — the exact
  "move beyond flow-level metrics" outcome.
- WI-5 delivers an **early slice of Level 3**: it catches unhealthy flows with no
  notification and gives a whole-fleet health view.

**Not yet reached (deliberately out of scope):** full Level 3 needs the 40%
volume-comparison Silent Failure rule, the Suppression Window, the Blocklist, and
SQLite state — the separate v1 work already in `docs/tdd.md`. Levels 4–5 (action)
remain blocked by [ADR-0001](../docs/adr/0001-read-only-agent.md) until detection
quality is proven, which is precisely what Level 2 evidence makes measurable.
