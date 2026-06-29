from __future__ import annotations

from typing import Any

from config import get_nested


class ControlConfigError(RuntimeError):
    pass


def controls_enabled(config: dict[str, Any]) -> bool:
    return bool(get_nested(config, ("controls", "enabled"), False))


def validate_control_config(config: dict[str, Any]) -> None:
    if not controls_enabled(config):
        return
    signing_secret = str(get_nested(config, ("slack", "signing_secret"), "") or "").strip()
    users = get_nested(config, ("slack", "allowed_user_ids"), []) or []
    actions = get_nested(config, ("controls", "allowed_actions"), []) or []
    control_key = str(get_nested(config, ("nexla", "control_service_key"), "") or "").strip()
    monitor_key = str(get_nested(config, ("nexla", "service_key"), "") or "").strip()
    if not signing_secret:
        raise ControlConfigError("controls.enabled requires slack.signing_secret")
    if not isinstance(users, list) or not [u for u in users if str(u).strip()]:
        raise ControlConfigError("controls.enabled requires non-empty slack.allowed_user_ids")
    if not isinstance(actions, list) or not [a for a in actions if str(a).strip()]:
        raise ControlConfigError("controls.enabled requires non-empty controls.allowed_actions")
    invalid_actions = {str(action) for action in actions} - {"pause", "activate"}
    if invalid_actions:
        raise ControlConfigError("controls.allowed_actions may only contain pause and activate")
    ttl = get_nested(config, ("controls", "action_ttl_seconds"), 900)
    try:
        if int(ttl) <= 0:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise ControlConfigError("controls.action_ttl_seconds must be a positive integer") from exc
    if not control_key and not monitor_key:
        raise ControlConfigError("controls.enabled requires nexla.control_service_key or nexla.service_key")
