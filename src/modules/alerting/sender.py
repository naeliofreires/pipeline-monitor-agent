from __future__ import annotations

import html
import json
import re
import urllib.request
from typing import Any, Protocol

from modules.controls.policy import ControlMetadata, build_action_value


_HTML_ANCHOR_PATTERN = re.compile(
    r"<a\s+[^>]*href=\\?[\"']([^\"']+?)\\?[\"'][^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)


class AlertSender(Protocol):
    def send(self, text: str, metadata: ControlMetadata | None = None) -> None:
        """Send alert text to the configured destination."""


class ConsoleAlertSender:
    def send(self, text: str, metadata: ControlMetadata | None = None) -> None:
        print(text)


class SlackBotAlertSender:
    def __init__(
        self,
        bot_token: str,
        channel_id: str,
        api_url: str = "https://slack.com/api/chat.postMessage",
        controls_config: dict[str, Any] | None = None,
        flow_url_template: str | None = None,
    ) -> None:
        self.bot_token = bot_token
        self.channel_id = channel_id
        self.api_url = api_url
        self.controls_config = controls_config or {}
        self.flow_url_template = (flow_url_template or "").strip()

    def send(self, text: str, metadata: ControlMetadata | None = None) -> None:
        formatted_text = _format_slack_message(text)
        body: dict[str, Any] = {"channel": self.channel_id, "text": formatted_text}
        blocks = _build_message_blocks(formatted_text, metadata, self.controls_config, self.flow_url_template)
        if blocks:
            body["blocks"] = blocks
        payload = json.dumps(body).encode("utf-8")
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
            response_body = response.read().decode("utf-8")

        try:
            result = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Slack API returned invalid JSON") from exc

        if not result.get("ok"):
            error = result.get("error", "unknown_error")
            raise RuntimeError(f"Slack API chat.postMessage failed: {error}")


def _format_slack_message(text: str) -> str:
    """Add Slack mrkdwn styling to Anomaly Alerts without changing plain messages."""
    text = _format_slack_links(text)
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


def _format_slack_links(text: str) -> str:
    """Convert Nexla HTML anchor links into Slack mrkdwn links."""
    def replace_anchor(match: re.Match[str]) -> str:
        url = html.unescape(match.group(1)).strip().rstrip("\\")
        label = html.unescape(match.group(2)).strip()
        return f"<{url}|{label}>" if url and label else label or url

    return _HTML_ANCHOR_PATTERN.sub(replace_anchor, text)


def _build_message_blocks(text: str, metadata: ControlMetadata | None, controls: dict[str, Any], flow_url_template: str = "") -> list[dict[str, Any]] | None:
    action_blocks = _build_action_blocks(metadata, controls, flow_url_template)
    control_blocks = _build_control_blocks(metadata, controls)
    if not _is_formatted_anomaly_alert(text) and not action_blocks and not control_blocks:
        return None
    blocks: list[dict[str, Any]] = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
    if action_blocks:
        blocks.extend(action_blocks)
    elif control_blocks:
        blocks.extend(control_blocks)
    return blocks


def _is_formatted_anomaly_alert(text: str) -> bool:
    first_line = text.splitlines()[0] if text else ""
    return first_line.startswith("*") and "Flow" in first_line


def _build_action_blocks(metadata: ControlMetadata | None, controls: dict[str, Any], flow_url_template: str) -> list[dict[str, Any]] | None:
    elements = []
    flow_url = _build_flow_url(metadata, flow_url_template)
    if flow_url:
        elements.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "Open Flow"},
            "url": flow_url,
        })
    control_blocks = _build_control_blocks(metadata, controls)
    if control_blocks:
        elements.extend(control_blocks[0].get("elements") or [])
    return [{"type": "actions", "elements": elements}] if elements else None


def _build_flow_url(metadata: ControlMetadata | None, flow_url_template: str) -> str | None:
    if metadata is None or metadata.flow_id is None or not flow_url_template:
        return None
    return flow_url_template.replace("{flow_id}", str(metadata.flow_id))


def _build_control_blocks(metadata: ControlMetadata | None, controls: dict[str, Any]) -> list[dict[str, Any]] | None:
    if not controls.get("enabled") or metadata is None or metadata.flow_id is None:
        return None
    if int(metadata.flow_id) in _flow_id_set(controls.get("protected_flows") or []):
        return None
    # Render only the destructive stop-control for now. The control backend still
    # supports activate for future use, but Slack Alerts should not invite users
    # to restart a Flow until that UX is explicitly validated.
    actions = [str(a) for a in controls.get("allowed_actions") or [] if str(a) == "pause"]
    if not actions:
        return None
    action_signing_secret = str(controls.get("action_signing_secret") or "")
    if not action_signing_secret:
        return None
    elements = []
    for action in actions:
        elements.append({
            "type": "button",
            "text": {"type": "plain_text", "text": action.title()},
            "action_id": f"flow_control_{action}",
            "value": build_action_value(
                int(metadata.flow_id),
                action,
                signing_secret=action_signing_secret,
            ),
            "style": "danger" if action == "pause" else "primary",
            "confirm": {"title": {"type": "plain_text", "text": f"{action.title()} flow?"}, "text": {"type": "mrkdwn", "text": f"Confirm {action} for flow {metadata.flow_id}."}, "confirm": {"type": "plain_text", "text": "Confirm"}, "deny": {"type": "plain_text", "text": "Cancel"}},
        })
    return [{"type": "actions", "elements": elements}]


def _flow_id_set(entries: Any) -> set[int]:
    flow_ids: set[int] = set()
    for entry in entries or []:
        value = entry.get("flow_id") if isinstance(entry, dict) else entry
        if value is not None:
            flow_ids.add(int(value))
    return flow_ids


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
            controls_config = dict((config or {}).get("controls", {}) or {})
            signing_secret = str(slack_config.get("signing_secret") or "").strip()
            if signing_secret:
                controls_config["action_signing_secret"] = signing_secret
            flow_url_template = str(slack_config.get("flow_url_template") or "").strip()
            return SlackBotAlertSender(bot_token, channel_id, api_url, controls_config, flow_url_template)

    return ConsoleAlertSender()
