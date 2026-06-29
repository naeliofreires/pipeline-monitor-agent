# Validation: anomaly-enrichment

Verdict: PASS

## Acceptance criteria and evidence

1. Notifications keep raw resource identity and resolve to the owning flow when possible.
   - Evidence: `tests/test_explicit_failure_alert.py:65-75` covers a `data_sink` notification resolving to flow `42` while preserving `resource_id=99`; the second notification remains alertable with `flow_id=None`.
2. Enrichment gathers Evidence and degrades to partial Evidence instead of dropping Anomalies.
   - Evidence: `tests/test_explicit_failure_alert.py:77-93` verifies health status, run status, metrics, and top error logs on the happy path, and `partial=True` when no flow id is available.
3. Classification and Alerts include Evidence.
   - Evidence: `tests/test_explicit_failure_alert.py:57-61` asserts the LLM payload contains Evidence; `tests/test_explicit_failure_alert.py:165-182` asserts the emitted Alert text includes the Evidence block and top error line.
4. RED org-health flows produce Alerts and are deduped against notification anomalies.
   - Evidence: `tests/test_explicit_failure_alert.py:95-97` verifies health-sweep dedupe; `tests/test_explicit_failure_alert.py:186-245` verifies `monitor_once` classifies both notification and no-notification RED-flow anomalies, with flow `42` deduped and flow `77` alerted (`tests/test_explicit_failure_alert.py:245`).
5. New Nexla reads are read-only and degrade safely.
   - Evidence: `tests/test_explicit_failure_alert.py:110-121` verifies adapter read methods return `None`/`[]` on SDK failures; `tests/test_explicit_failure_alert.py:194-197` installs a fail-fast flow-action sentinel (`ForbiddenFlows`) in the monitor integration test.

## Gates

- `PYTHONPATH=src python -m unittest discover -s tests`: PASS (`Ran 13 tests`, `OK (skipped=1)` — the skip is the real-LLM integration test, gated on `OPENCODE_API_KEY`).
- `PYTHONPATH=src python -m compileall src tests`: PASS.

## Gaps

- No real Nexla credential integration run was executed. The SDK call shapes were checked against the installed SDK, and adapter behavior is covered with fakes/mocks.
