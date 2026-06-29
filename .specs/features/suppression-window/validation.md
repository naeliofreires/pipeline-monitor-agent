# Validation: suppression-window

Verdict: PASS

## Acceptance criteria and evidence

1. SQLite stores emitted Alerts and answers `is_suppressed` within / after the window.
   - Evidence: `tests/test_suppression.py:25-30` records an Alert and asserts `is_suppressed` is true 1h later and false 3h later; `src/repositories/suppression_repository.py:30-44` is the indexed `is_suppressed` / `record_alert` implementation.
2. Suppression is scoped per `(flow_id, anomaly_type)`.
   - Evidence: `tests/test_suppression.py:32-35` verifies a recorded flow does not suppress a different flow or a different anomaly type.
3. Blocklisted flows never alert.
   - Evidence: `tests/test_suppression.py:51-55` (`should_alert` is false for a blocklisted flow, true for another); `tests/test_suppression.py:133-135` verifies an end-to-end tick over a blocklisted RED flow prints nothing and calls the LLM zero times.
4. Emitting an Alert suppresses repeats for the window, then re-alerts after it elapses.
   - Evidence: `tests/test_suppression.py:57-62` (`note_alerted` then `should_alert` false at +1h, true at +3h).
5. Anomalies with no resolved `flow_id` are never suppressed.
   - Evidence: `tests/test_suppression.py:64-67` (`note_alerted` is a no-op and `should_alert` stays true).
6. A persistently RED health-sweep flow alerts once across consecutive ticks.
   - Evidence: `tests/test_suppression.py:128-131` runs `monitor_once` twice against a shared store and asserts exactly one `[HIGH]` Alert and a single LLM classify call.
7. The check runs before enrichment/LLM and the repository is closed each tick.
   - Evidence: `src/monitor.py` filters with `should_alert(...)` before `enrich_anomaly`/`classify_anomaly`, records via `note_alerted(...)`, and closes the repository in a `finally` block.

## Gates

- `PYTHONPATH=src python -m unittest discover -s tests`: PASS (`Ran 22 tests`, `OK (skipped=1)` — the skip is the real-LLM integration test, gated on `OPENCODE_API_KEY`).
- `PYTHONPATH=src python -m compileall src tests`: PASS.

## Gaps

- No real Nexla credential integration run was executed; adapter behavior remains covered with fakes/mocks.
- SQLite persistence across an actual container restart is configured (`docker-compose.yml` named volume) but not exercised end-to-end in CI.
