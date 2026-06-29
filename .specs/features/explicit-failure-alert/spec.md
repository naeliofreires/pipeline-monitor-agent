# Explicit Failure Alert MVP

- Unread Nexla notifications are converted into Explicit Failure anomalies.
- Each anomaly is classified by the LLM before emitting an Alert through the configured sender.
- Alerts include Risk Classification, Explanation, Recommended Action, flow id, and detected time.
- `uncertain` LLM risk is treated as `high`; invalid/exceptional LLM responses fall back to `unknown` with the raw anomaly message and a safe action.
- Notifications are marked read after Alerts are emitted.
- No flow action methods are invoked.
