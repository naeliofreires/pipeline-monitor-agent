# Analysis Pipeline Reliability

How error/anomaly/classification analysis works end-to-end, what is trustworthy, and the known reliability risks. Source of truth for "can we trust the agent's findings?".

## The pipeline (deterministic detect → enrich → LLM classify → suppress → alert)

Orchestrated in `src/monitor.py:monitor_once()`. Per ADR-0002, **code decides what is an anomaly; the LLM only labels severity + writes prose.** An LLM hallucination cannot invent or hide a failure — the strongest trust property.

- **Detection** (deterministic):
  - `modules/detection/explicit_failure.py:detect_explicit_failures()` — Nexla notifications with level in `{ERROR, CRITICAL, FATAL}`. WARNING and others are ignored *and marked read*.
  - `modules/detection/health_sweep.py:detect_unhealthy_flows()` — RED org-health flows not already covered.
  - `modules/detection/silent_failure.py` — day-over-day volume drop ≥40% (`detect_silent_failures`) + run-over-run drop ≥80% (`detect_run_drop_failures`), guarded by `min_baseline=100` and a "looks running" status check.
- **Enrichment** (`modules/enrichment/enricher.py:enrich_anomaly()`): pulls health/run-status/metrics/run-summary/ERROR logs. Every adapter call try/except → sets `partial=True`, never drops the anomaly.
- **Classification** (`modules/classification/classifier.py:classify_anomaly()`): LLM via `adapters/llm_factory.py` (opencode default / openai). On any failure/bad shape → `_fallback()`. `uncertain` → `high`.
- Redaction (`modules/redaction.py`) masks credentials before Alert + LLM egress (ADR-0006, regex-based).

## Trust verdict

- **Architecture is sound.** Deterministic detection + LLM-as-explainer is the right call and is fail-safe almost everywhere (per-anomaly isolation in the loop, silent-failure sweep wrapped, enrichment degrades to partial).
- **Explicit failures + health sweep**: trustworthy (they ride on Nexla's own judgment), bounded by adapter blindness below.
- **Silent failures**: *plausible but unproven* — depends on two unverified assumptions (see risks #1 and #3).

## Known reliability risks (ranked)

1. **Detection goes blind silently.** `nexla_adapter.list_unhealthy_flows()` and `list_flow_volumes()` return `[]` on *any* exception. API down/changed ⇒ agent reports "zero anomalies" instead of "couldn't see". *Partially mitigated*: both catch blocks now log at WARNING ("...is blind this read..."), so blindness is visible in logs. Full dead-man's-switch / heartbeat that distinguishes "all healthy" from "blind" at the Alert level is still a follow-up.
2. **Missing record count → 0 is INTENTIONAL, not a bug** (initial review flagged it as a false-positive risk — reversed after reading ADR-0005 + `tests/test_silent_failure.py::ExtractVolumesTests`). `extract_flow_volumes()` treating null `latestRecordCount` as `0` is the canonical Silent Failure signal ("empty source extract, filter matching nothing, credential returning an empty page instead of erroring"). Skipping it would blind the agent to its core case. Residual concern — an in-progress early-UTC-day window reported as null could false-positive — is bounded by `min_baseline=100` + the running-status guard + suppression; the real mitigation is risk #3 (validate against live data), NOT changing this rule.
3. **`latestRecordCount` window semantics never validated** against real Nexla data (`.specs/features/silent-failure/validation.md` Gaps). Thresholds are calibrated in a vacuum. Day-granular early-UTC-day comparison is partial-vs-partial = noisy.
4. **LLM-failure fallback risk** — *fixed*: `classifier.py:_fallback()` now returns `high` for real detected anomalies (`HIGH_RISK_FALLBACK_TYPES` = explicit/silent/health), mirroring `uncertain`→`high`, so a transient LLM outage escalates instead of downgrading. A clean targeted `flow_scan` (no anomaly) still falls back to `unknown` — nothing to escalate.
5. **Hardcoded `size=25`** in `get_run_metrics()` / `get_run_summary()` — runs >25 deep return `None`; historical evidence (`avg_records_previous_runs`, `consecutive_failed_runs`) is capped at 25 rows.
6. **Regex redaction + third-party egress** (ADR-0006, accepted): unusual-format credentials pass; non-URL hostnames/table names go to opencode.ai/OpenAI by design.

## LIVE VALIDATION (2026-06-30, prod dataops.nexla.io, read-only) — org-health contract is WRONG

Ran the silent-failure/health-sweep reads against a real service key (6 flows, 1 RED). The org-health path was built on an *imagined* SDK contract; the real one differs on four axes, and detection that depends on it is currently non-functional:

- **A — Health Sweep never fired.** `flows.get_org_health_flows(health_status="RED")` raises `ValidationError` ("additional properties [health_status]…"). `list_unhealthy_flows()` always hit the `except` → `[]`. **FIXED**: call with NO `health_status`, filter `healthStatus == "RED"` client-side. Verified live: now returns RED flow 627806.
- **B — Silent Failure never fired.** `get_org_health_flows(from_date,to_date)` returns `metrics.data: []` for every window; only the no-arg call returns rows. The windowed day-over-day model in ADR-0005 didn't work. **FIXED**: pivoted to run-over-run — `list_flow_volumes()` reads the no-window latest-run counts, baseline = `SnapshotRepository.get_latest_record_count()` (most recent prior snapshot). See ADR-0005 Update (2026-06-30).
- **C — Response nesting.** Real shape `{"metrics": {"data": [...], "meta": {...}}, "status": 200}`. `_first_list(value, "data",…)` didn't descend into `metrics`. **FIXED**: added `"metrics"` to the search keys (it recurses).
- **D — Field name.** Rows use camelCase `originNodeId`/`healthStatus`/`latestRecordCount`/`latestRunId`. Detection's id lookup missed `originNodeId` → every row skipped. **FIXED**: added `originNodeId` alias in `extract_flow_volumes` + `detect_unhealthy_flows`. Verified live: all 6 flows parse (0 skipped).
- **#3 semantics CONFIRMED**: `latestRecordCount` is paired with `latestRunId` and only present in the no-window call ⇒ it is the *latest run's* count, not a window aggregate. Silent Failure is now run-over-run via `detect_run_drop_failures` + `metric_snapshots`.
- The unit test `tests/test_explicit_failure_alert.py::test_adapter_extracts_sdk_shaped_read_responses` encoded the imagined shape (`health_status` param, top-level `data`, snake_case `origin_node_id`) — which is why CI was green while prod was blind. NEVER trust these org-health tests as proof the contract is right.
- Config mismatch FIXED: `.env` used a stray `NEXLA_BASE_URL` that nothing reads (config.yaml, docker-compose, .env.example, and the SDK all key on `NEXLA_API_URL`; SDK fallback order is param → `NEXLA_API_URL` env → default `https://dataops.nexla.io/nexla-api`). Renamed the `.env` key to `NEXLA_API_URL` so the intended base URL actually takes effect (locally and in Docker, where `NEXLA_API_URL` otherwise defaults to QA).

## LIVE VALIDATION round 2 — enrichment shapes (get_flow_health / logs / run_status)

More imagined-contract bugs in the per-flow enrichment endpoints, found live and fixed:

- **`get_flow_health` health always `unknown` — FIXED.** Real shape nests under `metrics`: `{"metrics": {originNodeId, healthStatus, affectedResources: [{resourceType, latestRunId, latestRecordCount, latestErrorCount, errorSummary, status}]}, "status": 200}`. The adapter returned the outer envelope, so the enricher read top-level `healthStatus`/`latestRunId` → all `None`. Fix: `get_flow_health` unwraps `metrics` and lifts the primary (SOURCE) affectedResource's run fields (`_primary_health_resource`). Verified: 627806→RED, 627808→GREEN, with run id/records/errors populated.
- **`get_flow_error_logs` content lost — FIXED.** `search_flow_logs` works; logs nest under `logs.data`, and each row uses `log` (message text), `severity`, `timestamp` (epoch ms) — NOT `message`/`level`. `enricher._short_log` read `message`/`level` → surfaced only a timestamp. Fix: `_short_log` reads `log`/`severity` (message/level fallback). Verified: real error text ("4 records failed… Too many entries…") now surfaces.
- **"Logs: Inconclusive (read failed)" was misleading — FIXED.** `alert._logs_status` (and `monitor._scan_log_line`) keyed the Logs line on the overall `partial` flag, so a *successful* log read showed "read failed" whenever any other Evidence was missing. Fix: key the Logs line on `recent_run_log_check` (anomalies_found→Available, none_found→"No error log lines", inconclusive→"log read failed"), falling back to `partial` only when there is no log-check signal.
- **"⚠ Evidence is partial" was untrustworthy (cry-wolf) — FIXED.** `flows.get_run_status` returns `[]` on prod (→ `run_status=None`), and a flow-level anomaly (health_sweep / silent_failure, `resource_id=None`) has no per-resource metrics, so the old `if run_status is None or metrics is None: partial = True` fired on essentially EVERY alert even when health+run id+counts+logs all read fine. Fix (`enricher.enrich_anomaly`): `partial` now means a depended-on read genuinely failed — health unavailable, latest run unidentifiable, ERROR-log read failed, or no run volume at all (`records_this_run is None and errors_this_run is None`). run_status/metrics are best-effort and no longer drive `partial`. Verified live: 627806(RED)/627808(GREEN) with data read → `partial=False`; an unreadable flow → `partial=True`. `run_status` is still `None` (Nexla's org-health API does not expose run lifecycle status) but that alone no longer flags partial.

## SDK strict validation breaks targeted scans — FIXED

`flows.get(flow_id)` parses the response into a strict pydantic `FlowResponse`; a valid-but-unexpected payload (e.g. a `data_credentials[].name` that is `null`) raises `ValidationError`, which propagated out of `scan_flow` and failed the whole targeted scan ("Targeted scan for Flow 588132 failed: 2 validation errors for FlowResponse"). Fix (`nexla_adapter.get_flow`): catch the SDK error and fall back to the raw payload via `self._client.request("GET", f"/flows/{id}", params={"flows_only": 0})`, which returns the same `{flows: [...], data_sources: [...]}` envelope the rest of the code reads defensively; returns None only if the raw fetch also fails. Verified live: scan of 588132 now completes. The `client.request(...)` raw escape hatch is the mitigation for any other endpoint whose strict SDK model over-validates.

## Test gaps

`tests/` covers thresholds, fallback-in-isolation, partial-evidence, resilience-on-empty. NOT covered: exception (vs empty) path of `list_unhealthy_flows`/`list_flow_volumes`; run >25 deep; adversarial LLM (consistent `low` for high-severity); all three detectors in one `monitor_once`; real LLM adapter (skipped without `OPENCODE_API_KEY`).

Related: [[anomaly-enrichment-sdk-shapes]], [[silent-failure-volume-detection]].
