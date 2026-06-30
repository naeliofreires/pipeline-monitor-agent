from __future__ import annotations

import json
import logging
import threading
import urllib.request
from typing import Any, Callable

logger = logging.getLogger(__name__)


HELP_TEXT = "Commands: `help`, `scan`, `scan FLOW_ID`"


class SlackCommandExecutor:
    """Executes Slack Slash Commands for the monitoring agent."""

    def __init__(
        self,
        config: dict[str, Any],
        monitor_callback: Callable[[dict[str, Any]], None],
        flow_scan_callback: Callable[[dict[str, Any], int], str] | None = None,
    ) -> None:
        self.config = config
        self.monitor_callback = monitor_callback
        self.flow_scan_callback = flow_scan_callback

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
        return f"Unknown command `{command}`. {HELP_TEXT}"

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
        self._respond(response_url, text)

    def _respond(self, response_url: str | None, text: str) -> None:
        if not response_url:
            return
        body = json.dumps({"text": text}).encode()
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
