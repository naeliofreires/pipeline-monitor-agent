# Slack Slash Commands

Slack interactive button actions and Slash Commands share the HTTP server in `src/modules/controls/server.py:start_interaction_server()`.

- Button payloads post to `controls.interactions_path` and are routed to `ControlExecutor`.
- Slash Commands post to `controls.commands_path` and are routed to `src/modules/controls/commands.py:SlackCommandExecutor`.

Both paths verify the Slack request signature with `src/modules/controls/signature.py:verify_slack_signature()`. Slash Commands authorize `user_id`, `team_id`, and `channel_id` through `src/modules/controls/policy.py:authorize_slack_command()`.

Initial commands:

- `help` returns available commands.
- `scan` starts `monitor_once(config)` in a background thread and posts completion to Slack `response_url`.
