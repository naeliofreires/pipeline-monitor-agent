# Validation: silent-failure

Verdict: PASS

## Acceptance criteria and evidence

1. Volume drop at/above the threshold is flagged as a `silent_failure`; below is not.
   - Evidence: `tests/test_silent_failure.py::DetectSilentFailureTests.test_flags_drop_at_or_above_threshold` and `test_ignores_drop_below_threshold`; the rule is `src/modules/detection/silent_failure.py::detect_silent_failures`.
2. The adapter reads per-flow volume for one UTC date window and degrades gracefully.
   - Evidence: `src/adapters/nexla_adapter.py::list_flow_volumes` calls `get_org_health_flows(from_date=day, to_date=day)` and returns `[]` on any exception; the SilentFailureMonitorTests fake exercises today/yesterday windows end-to-end.
3. The snapshot repository persists and reads per-flow daily volume (upsert + indexed lookup).
   - Evidence: `tests/test_silent_failure.py::SnapshotRepositoryTests` (save/read, upsert same flow+day, `purge_older_than`); `src/repositories/snapshot_repository.py`.
4. Tiny baselines are ignored; per-flow threshold overrides the global one.
   - Evidence: `tests/test_silent_failure.py::DetectSilentFailureTests.test_ignores_missing_or_small_baseline` and `test_per_flow_threshold_overrides_global`.
5. Flows already reported this tick are excluded from Silent Failure detection.
   - Evidence: `tests/test_silent_failure.py::DetectSilentFailureTests.test_excludes_already_reported_flows`; in `src/monitor.py`, `existing_flow_ids` (notification + health-sweep flows) is passed as `exclude_flow_ids`.
6. A collapsed-volume flow alerts once across consecutive ticks and the snapshot is recorded.
   - Evidence: `tests/test_silent_failure.py::SilentFailureMonitorTests.test_volume_drop_alerts_once_and_records_snapshot` asserts a single `[HIGH]` "Silent Failure" alert, one LLM classify call keyed `(55, "silent_failure")`, and `get_record_count(55, today) == 50`.
7. The sweep cannot block other detection and the repositories are closed each tick.
   - Evidence: `src/monitor.py` wraps `detect_silent_failure_anomalies` in `try/except` (logs and continues with `[]`), and closes both `suppression` and `snapshots` in the `finally` block.

## Gates

- `PYTHONPATH=src python -m unittest discover -s tests`: PASS (`Ran 41 tests`, `OK (skipped=1)` — the skip is the real-LLM integration test, gated on `OPENCODE_API_KEY`). Includes threshold/min-baseline boundary tests, the snapshot cold-start fallback, the volume-read-failure resilience path, and mixed/increased-volume cases added after code review.
- `PYTHONPATH=src python -m compileall src tests`: PASS.

## Gaps

- No real Nexla credential run was executed. In particular, the exact meaning of `latestRecordCount` over a `from`/`to` org-health window is assumed to be "records in that window"; if Nexla scopes it differently, `volume_threshold_pct` / `min_baseline_records` may need tuning against live data.
- Day-granular comparison: early in a UTC day, today's partial window is compared to yesterday's same partial window as Nexla reports it. Intra-day (hourly) windows are out of scope for v1 (TDD open question on hourly vs daily record counts).
- Snapshot persistence across a real container restart is configured (the existing `docker-compose.yml` named volume already covers `metric_snapshots`, same DB file) but not exercised end-to-end in CI.
