# Slack Alert actions

Slack Alerts are sent by `src/modules/alerting/sender.py:SlackBotAlertSender`.

- Console output remains plain text through `ConsoleAlertSender`.
- Slack message text is converted to mrkdwn by `_format_slack_message()`.
- Slack blocks are built by `_build_message_blocks()`.
- Read-only navigation actions, such as the Open Flow button, use `slack.flow_url_template` and `ControlMetadata.flow_id`.
- Flow control actions are separate from navigation actions and are gated by the `controls` config.

Relevant tests live in `tests/test_explicit_failure_alert.py:AlertTests`.
