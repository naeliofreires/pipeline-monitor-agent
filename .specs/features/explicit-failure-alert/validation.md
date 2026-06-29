# Validation: explicit-failure-alert

Diff range: uncommitted working tree for explicit-failure-alert increment

Verdict: PASS

## Acceptance criteria and evidence

1. Unread Nexla notifications are converted into Explicit Failure anomalies.
   - Evidence: `tests/test_explicit_failure_alert.py:82-84` supplies one unread ERROR flow notification from `list_unread_notifications`; `tests/test_explicit_failure_alert.py:104` asserts `self.assertLess(events.index(("classify", 10)), next(i for i, event in enumerate(events) if event[0] == "mark_read"))`, proving notification id 10 was detected and classified before mark-read; `tests/test_explicit_failure_alert.py:105` asserts `self.assertIn("Risk Classification: high", output.getvalue())`, proving an alert was printed for the detected anomaly.
2. Each anomaly is classified by the LLM before emitting an Alert through the configured sender.
   - Evidence: `tests/test_explicit_failure_alert.py:93-95` records LLM classification for notification id 10; `tests/test_explicit_failure_alert.py:104` asserts `self.assertLess(events.index(("classify", 10)), next(i for i, event in enumerate(events) if event[0] == "mark_read"))`; `tests/test_explicit_failure_alert.py:105-107` assert alert output contains the LLM-derived fields: `self.assertIn("Risk Classification: high", output.getvalue())`, `self.assertIn("Explanation: Known failure notification", output.getvalue())`, and `self.assertIn("Recommended Action: Restart flow", output.getvalue())`.
3. Alerts include Risk Classification, Explanation, Recommended Action, flow id, and detected time.
   - Evidence: `tests/test_explicit_failure_alert.py:62-66` asserts `self.assertIn("Risk Classification: high", text)`, `self.assertIn("Explanation: Destination rejected records", text)`, `self.assertIn("Recommended Action: Fix credentials", text)`, `self.assertIn("Flow ID: 42", text)`, and `self.assertIn("Detected Time: 2026-01-01T00:00:00+00:00", text)`.
4. `uncertain` LLM risk is treated as `high`.
   - Evidence: `tests/test_explicit_failure_alert.py:36` asserts `self.assertEqual(result.risk_classification, "high")` after an LLM response containing `"risk_classification": "uncertain"`; `tests/test_explicit_failure_alert.py:37-38` assert the explanation and recommended action are preserved: `self.assertEqual(result.explanation, "maybe")`, `self.assertEqual(result.recommended_action, "inspect")`.
5. Invalid/exceptional LLM responses fall back to `unknown` with the raw anomaly message and a safe action.
   - Evidence: `tests/test_explicit_failure_alert.py:43-44` exercises invalid and exceptional LLM responses; `tests/test_explicit_failure_alert.py:47-49` asserts `self.assertEqual(result.risk_classification, "unknown")`, `self.assertEqual(result.explanation, "raw failure")`, and `self.assertIn("Review the Nexla notification", result.recommended_action)`.
6. Notifications are marked read after Alerts are emitted.
   - Evidence: `tests/test_explicit_failure_alert.py:104` asserts `self.assertLess(events.index(("classify", 10)), next(i for i, event in enumerate(events) if event[0] == "mark_read"))`; `tests/test_explicit_failure_alert.py:108` asserts `self.assertEqual(events[-1], ("mark_read", [10]))`, proving mark-read is the final recorded adapter event after alert generation returns.
7. No flow action methods are invoked.
   - Evidence: `tests/test_explicit_failure_alert.py:78-80` installs a `ForbiddenFlows` sentinel that raises `AssertionError(f"flow action must not be called: {name}")` on any flow method access, and `tests/test_explicit_failure_alert.py:102` runs `monitor_once(config)` without that failure. There is no separate unittest assertion expression for this negative condition, but the sentinel would fail the test on violation.

## Gates

- `PYTHONPATH=src python -m unittest discover -s tests`: PASS (`Ran 4 tests`, `OK`).
- `PYTHONPATH=src python -m compileall src tests`: PASS.

## Mutation/discrimination sensor

Executed in scratch copy only: `/var/folders/wh/_ggpx1y555n0bjcqh27z0dfm0000gn/T/opencode/pipeline-monitor-mutation`; real tree was not mutated.

- Mutation `uncertain_not_high` (`uncertain` no longer normalized to `high`): relevant tests FAILED as expected.
- Mutation `fallback_not_raw_message` (fallback explanation no longer raw anomaly message): relevant tests FAILED as expected.
- Mutation `mark_read_before_alert` (mark-read moved before alert/classification loop): relevant tests FAILED as expected.

## Gaps

- None blocking. Note: the no-flow-actions criterion is covered by a fail-fast sentinel rather than a dedicated `self.assert...` expression.
