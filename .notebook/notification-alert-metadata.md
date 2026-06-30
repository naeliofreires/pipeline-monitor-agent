# Notification Alert Metadata

Explicit Failure notification metadata is mapped in `src/modules/detection/explicit_failure.py:detect_explicit_failures()` into `src/modules/detection/anomaly.py:Anomaly`.

Operator-facing formatting lives in `src/modules/alerting/alert.py:build_anomaly_alert_text()`. The Alert includes notification id/level/created time, resource type/id, owner name/email, org name, access roles, read time, and updated time when present.

The LLM payload is built in `src/modules/classification/classifier.py:_payload()` and includes the same notification metadata so classification can reference owner/resource/org Evidence without changing detection semantics.
