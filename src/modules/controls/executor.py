from __future__ import annotations

import json
import logging
import queue
import threading
import urllib.request
from typing import Any

from modules.controls.policy import ParsedAction

logger = logging.getLogger(__name__)


class ControlExecutor:
    def __init__(self, adapter: Any, audit: Any) -> None:
        self.adapter = adapter
        self.audit = audit
        self._q: queue.Queue[tuple[ParsedAction, dict[str, Any], str | None]] = queue.Queue()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def enqueue(self, action: ParsedAction, payload: dict[str, Any], response_url: str | None) -> None:
        user = (payload.get("user") or {}).get("id")
        logger.info(
            "Enqueued Slack flow control action=%s flow_id=%s actor=%s correlation_id=%s",
            action.action,
            action.flow_id,
            user,
            action.correlation_id,
        )
        self._q.put((action, payload, response_url))

    def _run(self) -> None:
        while True:
            action, payload, response_url = self._q.get()
            self.execute_once(action, payload, response_url)

    def execute_once(self, action: ParsedAction, payload: dict[str, Any], response_url: str | None) -> None:
        user = (payload.get("user") or {}).get("id")
        team = (payload.get("team") or {}).get("id")
        channel = (payload.get("channel") or {}).get("id")
        try:
            logger.info(
                "Executing Slack flow control action=%s flow_id=%s actor=%s team=%s channel=%s correlation_id=%s",
                action.action,
                action.flow_id,
                user,
                team,
                channel,
                action.correlation_id,
            )
            flow = self.adapter.get_flow(action.flow_id) or {}
            previous = str(flow.get("status") or "") or None
            desired = "PAUSED" if action.action == "pause" else "ACTIVE"
            logger.info(
                "Flow control current status flow_id=%s previous_status=%s desired_status=%s correlation_id=%s",
                action.flow_id,
                previous,
                desired,
                action.correlation_id,
            )
            if previous == desired:
                self.audit.record(
                    result="no-op",
                    actor_user_id=user,
                    team_id=team,
                    channel_id=channel,
                    action=action.action,
                    flow_id=action.flow_id,
                    previous_status=previous,
                    correlation_id=action.correlation_id,
                )
                self._respond(response_url, f"Flow {action.flow_id} already {desired}.")
            else:
                if action.action == "pause":
                    sdk_response = self.adapter.pause_flow(action.flow_id)
                elif action.action == "activate":
                    sdk_response = self.adapter.activate_flow(action.flow_id)
                else:
                    raise ValueError("unsupported action")
                logger.info(
                    "Flow control SDK mutation completed action=%s flow_id=%s previous_status=%s sdk_response=%s correlation_id=%s",
                    action.action,
                    action.flow_id,
                    previous,
                    sdk_response,
                    action.correlation_id,
                )
                self.audit.record(
                    result="completed",
                    actor_user_id=user,
                    team_id=team,
                    channel_id=channel,
                    action=action.action,
                    flow_id=action.flow_id,
                    previous_status=previous,
                    correlation_id=action.correlation_id,
                )
                self._respond(response_url, f"Flow {action.flow_id} {action.action} requested.")
        except Exception as exc:
            logger.exception(
                "Flow control failed action=%s flow_id=%s actor=%s correlation_id=%s",
                action.action,
                action.flow_id,
                user,
                action.correlation_id,
            )
            self.audit.record(
                result="failed",
                actor_user_id=user,
                team_id=team,
                channel_id=channel,
                action=action.action,
                flow_id=action.flow_id,
                reason=str(exc),
                correlation_id=action.correlation_id,
            )
            self._respond(response_url, f"Flow control failed: {exc}")

    def _respond(self, response_url: str | None, text: str) -> None:
        if not response_url:
            return
        data = json.dumps({"text": text}).encode()
        try:
            urllib.request.urlopen(urllib.request.Request(response_url, data=data, headers={"Content-Type":"application/json"}, method="POST"), timeout=3)
        except Exception:
            pass
