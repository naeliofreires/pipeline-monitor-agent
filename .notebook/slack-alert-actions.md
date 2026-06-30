# Slack Alert actions

Slack Alerts are sent by `src/modules/alerting/sender.py:SlackBotAlertSender`.

- Console output remains plain text through `ConsoleAlertSender`.
- Slack message text is converted to mrkdwn by `_format_slack_message()`.
- Alert text from `src/modules/alerting/alert.py:build_anomaly_alert_text()` uses a system-card layout: title, Flow, Risk Level, preformatted `Notification Evidence` for Explicit Failure metadata, preformatted `Scan Result`, Explanation, and Next Steps.
- Targeted `/pipeline scan FLOW_ID` follow-up text from `src/monitor.py:build_flow_scan_text()` uses the same system-card layout and keeps the user-facing language in English.
- Explicit Failure notification/resource/org metadata is grouped as an `Enrichment Log` preformatted header in Slack while console output remains plain text.
- Slack blocks are built by `_build_message_blocks()`.
- Read-only navigation actions, such as the Open Flow button, use `slack.flow_url_template` and `ControlMetadata.flow_id`.
- Flow control actions are separate from navigation actions and are gated by the `controls` config.
- Slack control buttons are contextual: `ACTIVE`/`RUNNING`/healthy Flow status renders `Pause` when allowed; `PAUSED`/inactive/stopped status renders `Activate` when allowed. Unknown status renders no control button.

Relevant tests live in `tests/test_explicit_failure_alert.py:AlertTests`.
