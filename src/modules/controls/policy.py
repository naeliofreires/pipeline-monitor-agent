from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ControlMetadata:
    flow_id: int | None
    flow_name: str | None = None


@dataclass(frozen=True)
class ParsedAction:
    flow_id: int
    action: str
    issued_at: int
    correlation_id: str


def _encode_json(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()


def _decode_json(value: str) -> dict[str, Any]:
    decoded = base64.urlsafe_b64decode(value.encode()).decode()
    data = json.loads(decoded)
    if not isinstance(data, dict):
        raise ValueError("malformed action value")
    return data


def _signature(data: dict[str, Any], secret: str) -> str:
    unsigned = {key: data[key] for key in sorted(data) if key != "sig"}
    raw = json.dumps(unsigned, separators=(",", ":"), sort_keys=True).encode()
    return hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def build_action_value(
    flow_id: int,
    action: str,
    now: int | None = None,
    nonce: str | None = None,
    signing_secret: str | None = None,
) -> str:
    if not signing_secret:
        raise ValueError("action signing secret is required")
    payload = {
        "flow_id": int(flow_id),
        "action": action,
        "iat": int(now or time.time()),
        "nonce": nonce or str(uuid.uuid4()),
    }
    payload["sig"] = _signature(payload, signing_secret)
    return _encode_json(payload)


def parse_action_value(value: str, ttl_seconds: int, now: int | None = None, signing_secret: str | None = None) -> ParsedAction:
    if not signing_secret:
        raise ValueError("action signing secret is required")
    try:
        data = _decode_json(value)
        actual = str(data.get("sig") or "")
        if not actual or not hmac.compare_digest(actual, _signature(data, signing_secret)):
            raise ValueError("invalid action signature")
        parsed = ParsedAction(int(data["flow_id"]), str(data["action"]), int(data["iat"]), str(data["nonce"]))
    except Exception as exc:
        raise ValueError("malformed action value") from exc
    current_time = int(now or time.time())
    if parsed.issued_at - current_time > 300:
        raise ValueError("future action value")
    if current_time - parsed.issued_at > int(ttl_seconds):
        raise ValueError("expired action value")
    return parsed


def authorize(parsed: ParsedAction, payload: dict[str, Any], config: dict[str, Any]) -> str | None:
    controls = config.get("controls", {}) if isinstance(config.get("controls"), dict) else {}
    slack = config.get("slack", {}) if isinstance(config.get("slack"), dict) else {}
    if not controls.get("enabled"):
        return "controls disabled"
    if parsed.action not in set(map(str, controls.get("allowed_actions") or [])):
        return "action not allowed"
    if parsed.flow_id in _flow_id_set(controls.get("protected_flows") or []):
        return "protected flow"
    user = (payload.get("user") or {}).get("id")
    if user not in set(map(str, slack.get("allowed_user_ids") or [])):
        return "user not allowed"
    team = (payload.get("team") or {}).get("id")
    channel = (payload.get("channel") or {}).get("id")
    if slack.get("allowed_team_ids") and team not in set(map(str, slack.get("allowed_team_ids") or [])):
        return "team not allowed"
    if slack.get("allowed_channel_ids") and channel not in set(map(str, slack.get("allowed_channel_ids") or [])):
        return "channel not allowed"
    return None


def _flow_id_set(entries: Any) -> set[int]:
    flow_ids: set[int] = set()
    for entry in entries or []:
        value = entry.get("flow_id") if isinstance(entry, dict) else entry
        if value is not None:
            flow_ids.add(int(value))
    return flow_ids
