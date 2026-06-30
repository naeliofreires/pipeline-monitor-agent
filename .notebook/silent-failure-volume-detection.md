# Silent Failure Volume Detection

Silent Failure detection is implemented in `src/modules/detection/silent_failure.py` and wired by `src/monitor.py:_scan_silent_failures()`.

There are two checks:

- Day-over-day: current Flow volume versus the same window yesterday, using `detection.volume_threshold_pct` and `detection.min_baseline_records`.
- Exceptional run-over-run: current Flow volume versus the previous same-day snapshot captured before the current tick upserts the snapshot, using `detection.run_drop_threshold_pct` and `detection.min_run_baseline_records`.

Day-over-day remains the primary signal. Run-over-run only adds a `silent_failure` Anomaly when the Flow is not already reported in the tick and the day-over-day check did not already fire for that Flow.
