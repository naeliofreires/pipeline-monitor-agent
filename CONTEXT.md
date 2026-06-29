# Pipeline Monitoring Agent

A proactive agent that watches Nexla flows, finds problems, explains them in plain language, and tells the operator what to do. The automatic monitor is read-only — it only watches and reports. Supervised, user-initiated Slack flow controls are an explicit ADR 0007 exception, preferably using a separate service key.

## Language

### Flows and problems

**Flow**:
A Nexla data pipeline made up of a source, a transform step, and a destination. This is the main thing the agent monitors.
_Avoid_: pipeline, job, data flow (different term used in admin-api)

**Anomaly**:
A problem detected in a flow — something that does not look right. There are three types: Explicit Failure, Silent Failure, and `health_sweep`.
_Avoid_: error, issue, problem, incident

**Explicit Failure**:
An anomaly that Nexla itself found and reported through a notification.
_Avoid_: notification error, platform error

**Silent Failure**:
An anomaly found by comparing volume numbers — the flow is running but processing 40% or more fewer records than it did at the same time yesterday. Nexla did not send a notification for it.
_Avoid_: volume anomaly, metric alert, quiet failure

**Health Sweep** (`health_sweep`):
An anomaly found by the org health sweep when a Flow appears RED and there is no already-processed Nexla notification for it.
_Avoid_: health alert, org health issue, red flow notification

**Enrichment**:
The read-only step that gathers a flow's health, latest run status, record/error counts, and error log lines after an Anomaly is detected and before it is classified.
_Avoid_: hydration, lookup, fetch

**Evidence**:
The enriched data points attached to an Anomaly and sent to the LLM.
_Avoid_: context, details

### Agent outputs

**Alert**:
A message emitted by the agent when it finds an Anomaly. During development it defaults to console output, and it can be sent through the opt-in Slack bot sender. It includes the flow name, the type of problem, the Risk Classification, a plain-language explanation, and a Recommended Action.
_Avoid_: notification (Nexla's own term), message

**Recommended Action**:
A suggestion from the LLM, included in the Alert, about what the operator should do. The agent never runs this action itself.
_Avoid_: automated action, command, action

**Risk Classification**:
The LLM's judgment of how serious an Anomaly is: `low`, `high`, or `uncertain`. If the result is `uncertain`, it is treated as `high`. This drives how urgent the Alert looks.
_Avoid_: severity, priority, risk level

### Noise control

**Suppression Window**:
A time period (default: 2 hours) during which the agent will not send another Alert for the same flow and the same type of problem. This stops repeated alerts for the same issue.
_Avoid_: cooldown, debounce, silence period

**Alert Sender**:
The delivery seam for Alerts. The default sender prints to console; the Slack bot sender posts to a configured Slack channel when explicitly enabled.
_Avoid_: notifier, transport plugin

**Blocklist**:
A list of flows that the agent should never alert on. Used for flows that are naturally noisy and would create too many false alerts.
_Avoid_: exclusion list, ignore list, allowlist
