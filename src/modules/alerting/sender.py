from __future__ import annotations

import json
import urllib.request
from typing import Any, Protocol


class AlertSender(Protocol):
    def send(self, text: str) -> None:
        """Send alert text to the configured destination."""


class ConsoleAlertSender:
    def send(self, text: str) -> None:
        print(text)


class SlackBotAlertSender:
    def __init__(
        self,
        bot_token: str,
        channel_id: str,
        api_url: str = "https://slack.com/api/chat.postMessage",
    ) -> None:
        self.bot_token = bot_token
        self.channel_id = channel_id
        self.api_url = api_url

    def send(self, text: str) -> None:
        payload = json.dumps({"channel": self.channel_id, "text": _format_slack_message(text)}).encode("utf-8")
        request = urllib.request.Request(
            self.api_url,
            data=payload,
            headers={
                "Authorization": f"Bearer {self.bot_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        with urllib.request.urlopen(request) as response:
            body = response.read().decode("utf-8")

        try:
            result = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Slack API returned invalid JSON") from exc

        if not result.get("ok"):
            error = result.get("error", "unknown_error")
            raise RuntimeError(f"Slack API chat.postMessage failed: {error}")


def _format_slack_message(text: str) -> str:
    """Add Slack mrkdwn styling to Anomaly Alerts without changing plain messages."""
    lines = text.splitlines()
    if len(lines) < 2 or "Flow" not in lines[0] or not set(lines[1]) <= {"━"}:
        return text

    styled = [f"*{lines[0]}*"]
    for line in lines[2:]:
        if line.startswith("Explanation: "):
            styled.append(f"*Explanation:* {line.removeprefix('Explanation: ')}")
        elif line.startswith("Recommended Action: "):
            styled.append(f"*Recommended Action:* {line.removeprefix('Recommended Action: ')}")
        elif line.startswith("Flow ID: "):
            styled.append(f"_{line}_")
        else:
            styled.append(line)
    return "\n".join(styled)


def build_alert_sender(config: dict[str, Any] | None = None) -> AlertSender:
    """Build an alert sender. Slack is opt-in; default remains console-only.

    Slack is enabled only when slack.enabled is truthy and both bot_token and
    channel_id are non-empty.
    """
    slack_config = (config or {}).get("slack", {})
    if isinstance(slack_config, dict) and slack_config.get("enabled"):
        bot_token = str(slack_config.get("bot_token") or "").strip()
        channel_id = str(slack_config.get("channel_id") or "").strip()
        if bot_token and channel_id:
            api_url = str(slack_config.get("api_url") or "https://slack.com/api/chat.postMessage")
            return SlackBotAlertSender(bot_token, channel_id, api_url)

    return ConsoleAlertSender()
