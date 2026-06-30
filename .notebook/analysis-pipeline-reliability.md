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

1. **Detection goes blind silently.** `nexla_adapter.list_unhealthy_flows()` and `list_flow_volumes()` return `[]` on *any* exception. API down/changed ⇒ agent reports "zero anomalies" instead of "couldn't see". No dead-man's-switch / heartbeat distinguishing "all healthy" from "blind".
2. **False-positive silent_failure via field parsing.** `silent_failure.py:extract_flow_volumes()` treats a missing record count as `0`. If the real field name isn't in the coalescing list, count=0 vs baseline≥100 ⇒ 100% "drop" ⇒ false Silent Failure (when status looks running). The pervasive camelCase/snake_case `get_value(...)` cascades signal the real API contract is not actually known.
3. **`latestRecordCount` window semantics never validated** against real Nexla data (`.specs/features/silent-failure/validation.md` Gaps). Thresholds are calibrated in a vacuum. Day-granular early-UTC-day comparison is partial-vs-partial = noisy.
4. **LLM-failure fallback risk = `unknown` (⚪), not `high`.** A transient LLM outage *downgrades* a real anomaly's visual urgency, while `uncertain` from the LLM correctly escalates to `high`. Fail-safe should be the opposite.
5. **Hardcoded `size=25`** in `get_run_metrics()` / `get_run_summary()` — runs >25 deep return `None`; historical evidence (`avg_records_previous_runs`, `consecutive_failed_runs`) is capped at 25 rows.
6. **Regex redaction + third-party egress** (ADR-0006, accepted): unusual-format credentials pass; non-URL hostnames/table names go to opencode.ai/OpenAI by design.

## Test gaps

`tests/` covers thresholds, fallback-in-isolation, partial-evidence, resilience-on-empty. NOT covered: exception (vs empty) path of `list_unhealthy_flows`/`list_flow_volumes`; run >25 deep; adversarial LLM (consistent `low` for high-severity); all three detectors in one `monitor_once`; real LLM adapter (skipped without `OPENCODE_API_KEY`).

Related: [[anomaly-enrichment-sdk-shapes]], [[silent-failure-volume-detection]].
