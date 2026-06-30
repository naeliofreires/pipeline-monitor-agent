from __future__ import annotations

import json
import logging
import threading
import urllib.request
from typing import Any, Callable

from modules.alerting.sender import _build_message_blocks, _format_slack_message
from modules.controls.policy import ControlMetadata

logger = logging.getLogger(__name__)


HELP_TEXT = "Commands: `help`, `scan`, `scan FLOW_ID`, `monitoring FLOW_ID`, `monitoring remove FLOW_ID`, `monitoring list`"


class SlackCommandExecutor:
    """Executes Slack Slash Commands for the monitoring agent."""

    def __init__(
        self,
        config: dict[str, Any],
        monitor_callback: Callable[[dict[str, Any]], None],
        flow_scan_callback: Callable[[dict[str, Any], int], str] | None = None,
        monitoring_callback: Callable[[dict[str, Any], str, int | None, dict[str, str | None]], str] | None = None,
    ) -> None:
        self.config = config
        self.monitor_callback = monitor_callback
        self.flow_scan_callback = flow_scan_callback
        self.monitoring_callback = monitoring_callback

    def handle(self, form: dict[str, list[str]]) -> str:
        text = ((form.get("text") or [""])[0] or "").strip()
        command = text.split(maxsplit=1)[0].lower() if text else "help"
        response_url = (form.get("response_url") or [None])[0]

        if command in {"help", ""}:
            return HELP_TEXT
        if command == "scan":
            args = text.split()[1:]
            if len(args) > 1:
                return "Usage: `/pipeline scan` or `/pipeline scan FLOW_ID`."
            if args:
                try:
                    flow_id = int(args[0])
                    if flow_id <= 0:
                        raise ValueError
                except ValueError:
                    return "Invalid Flow ID. Use a positive numeric Flow ID, for example `/pipeline scan 42`."
                threading.Thread(target=self._run_flow_scan, args=(response_url, flow_id), daemon=True).start()
                return f"Starting a targeted scan for Flow {flow_id}. I’ll post the analysis here when it finishes."
            threading.Thread(target=self._run_scan, args=(response_url,), daemon=True).start()
            return "Starting a monitoring scan. I’ll post the result here when it finishes."
        if command == "monitoring":
            return self._handle_monitoring(text, form)
        return f"Unknown command `{command}`. {HELP_TEXT}"

    def _handle_monitoring(self, text: str, form: dict[str, list[str]]) -> str:
        if self.monitoring_callback is None:
            return "Continuous Flow monitoring is not configured."
        args = text.split()[1:]
        channel_id = (form.get("channel_id") or [None])[0]
        user_id = (form.get("user_id") or [None])[0]
        metadata = {"channel_id": channel_id, "user_id": user_id, "team_id": (form.get("team_id") or [None])[0]}
        if not channel_id:
            return "Cannot register monitoring without a Slack channel ID."
        if args == ["list"]:
            return self.monitoring_callback(self.config, "list", None, metadata)
        if len(args) == 1:
            flow_id = self._parse_flow_id(args[0])
            if flow_id is None:
                return "Invalid Flow ID. Use a positive numeric Flow ID, for example `/pipeline monitoring 42`."
            return self.monitoring_callback(self.config, "register", flow_id, metadata)
        if len(args) == 2 and args[0].lower() == "remove":
            flow_id = self._parse_flow_id(args[1])
            if flow_id is None:
                return "Invalid Flow ID. Use a positive numeric Flow ID, for example `/pipeline monitoring remove 42`."
            return self.monitoring_callback(self.config, "remove", flow_id, metadata)
        return "Usage: `/pipeline monitoring FLOW_ID`, `/pipeline monitoring remove FLOW_ID`, or `/pipeline monitoring list`."

    def _parse_flow_id(self, value: str) -> int | None:
        try:
            flow_id = int(value)
            if flow_id <= 0:
                raise ValueError
        except ValueError:
            return None
        return flow_id

    def _run_scan(self, response_url: str | None) -> None:
        try:
            self.monitor_callback(self.config)
        except Exception as exc:
            logger.exception("Slack scan command failed")
            self._respond(response_url, f"Monitoring scan failed: {exc}")
            return
        self._respond(response_url, "Monitoring scan finished.")

    def _run_flow_scan(self, response_url: str | None, flow_id: int) -> None:
        if self.flow_scan_callback is None:
            self._respond(response_url, "Targeted Flow scan is not configured.")
            return
        try:
            text = self.flow_scan_callback(self.config, flow_id)
        except Exception as exc:
            logger.exception("Slack targeted scan command failed for flow %s", flow_id)
            self._respond(response_url, f"Targeted scan for Flow {flow_id} failed: {exc}")
            return
        self._respond(response_url, text, self._flow_health_metadata(flow_id, text))

    def _respond(self, response_url: str | None, text: str, metadata: ControlMetadata | None = None) -> None:
        if not response_url:
            return
        formatted_text = _format_slack_message(text)
        payload: dict[str, Any] = {"text": formatted_text}
        if metadata is not None:
            controls_config = dict((self.config or {}).get("controls", {}) or {})
            signing_secret = str((self.config or {}).get("slack", {}).get("signing_secret") or "").strip()
            if signing_secret:
                controls_config["action_signing_secret"] = signing_secret
            flow_url_template = str((self.config or {}).get("slack", {}).get("flow_url_template") or "").strip()
            blocks = _build_message_blocks(formatted_text, metadata, controls_config, flow_url_template)
            if blocks:
                payload["blocks"] = blocks
        body = json.dumps(payload).encode()
        request = urllib.request.Request(
            response_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(request, timeout=3)
        except Exception:
            logger.warning("Failed to send Slack command follow-up response", exc_info=True)

    def _flow_health_metadata(self, flow_id: int, text: str) -> ControlMetadata | None:
        if "Flow Health Status" not in text:
            return None
        return ControlMetadata(
            flow_id=flow_id,
            flow_status=self._scan_text_value(text, "Status") or self._scan_text_value(text, "Health"),
        )

    def _scan_text_value(self, text: str, label: str) -> str | None:
        prefix = f"{label}"
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith(prefix) or ":" not in stripped:
                continue
            value = stripped.split(":", 1)[1].strip()
            return value if value and value != "unknown" else None
        return None
