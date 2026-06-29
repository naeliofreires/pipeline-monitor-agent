from __future__ import annotations

import json
import logging
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from modules.controls.policy import authorize, parse_action_value
from modules.controls.signature import verify_slack_signature

logger = logging.getLogger(__name__)


def start_interaction_server(config: dict[str, Any], audit: Any, executor: Any) -> ThreadingHTTPServer:
    controls = config.get("controls", {})
    slack = config.get("slack", {})
    path = str(controls.get("interactions_path") or "/slack/interactions")
    ttl = int(controls.get("action_ttl_seconds") or 900)
    secret = str(slack.get("signing_secret") or "")
    if not secret:
        raise ValueError("slack.signing_secret is required for interaction server")

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path != path:
                logger.warning("Rejected Slack interaction on invalid path: %s", self.path)
                audit.record(result="denied", reason="invalid interaction path")
                self._reply(403, "denied"); return
            if not verify_slack_signature(raw, self.headers.get("X-Slack-Request-Timestamp", ""), self.headers.get("X-Slack-Signature", ""), secret):
                logger.warning("Rejected Slack interaction with invalid signature")
                audit.record(result="denied", reason="invalid Slack signature")
                self._reply(403, "denied"); return
            try:
                form = urllib.parse.parse_qs(raw.decode())
                payload = json.loads(form.get("payload", [""])[0])
                if payload.get("type") != "block_actions":
                    raise ValueError("unsupported Slack payload type")
                value = payload["actions"][0].get("value", "")
                parsed = parse_action_value(value, ttl, signing_secret=secret)
                reason = authorize(parsed, payload, config)
                user = (payload.get("user") or {}).get("id"); team = (payload.get("team") or {}).get("id"); channel = (payload.get("channel") or {}).get("id")
                if reason:
                    logger.warning(
                        "Denied Slack flow control action=%s flow_id=%s actor=%s reason=%s correlation_id=%s",
                        parsed.action,
                        parsed.flow_id,
                        user,
                        reason,
                        parsed.correlation_id,
                    )
                    audit.record(result="denied", actor_user_id=user, team_id=team, channel_id=channel, action=parsed.action, flow_id=parsed.flow_id, reason=reason, correlation_id=parsed.correlation_id)
                    self._reply(200, "Denied."); return
                logger.info(
                    "Accepted Slack flow control action=%s flow_id=%s actor=%s team=%s channel=%s correlation_id=%s",
                    parsed.action,
                    parsed.flow_id,
                    user,
                    team,
                    channel,
                    parsed.correlation_id,
                )
                audit.record(result="accepted", actor_user_id=user, team_id=team, channel_id=channel, action=parsed.action, flow_id=parsed.flow_id, correlation_id=parsed.correlation_id)
                executor.enqueue(parsed, payload, payload.get("response_url"))
                self._reply(200, "Control request accepted.")
            except Exception as exc:
                audit.record(result="denied", reason=str(exc))
                self._reply(200, "Denied.")

        def _reply(self, code: int, text: str) -> None:
            body = json.dumps({"text": text}).encode()
            self.send_response(code); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    port = controls.get("interactions_port")
    server = ThreadingHTTPServer((str(controls.get("interactions_host") or "127.0.0.1"), int(8080 if port is None else port)), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
