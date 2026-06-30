from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


class RouterArgumentError(ValueError):
    """Raised when the LLM picked a tool but its arguments are missing or unusable."""


@dataclass(frozen=True)
class RouterContext:
    """Channel-agnostic context for a routed request. Terminal uses channel_id='cli'."""

    config: dict[str, Any]
    channel_id: str | None = None
    user_id: str | None = None


@dataclass(frozen=True)
class RouterCallbacks:
    """The existing behaviors the router may invoke. Injected so this layer never imports monitor."""

    scan_flow: Callable[[dict[str, Any], int], str]
    scan_org: Callable[[dict[str, Any]], Any]
    latest_runs: Callable[[dict[str, Any], int, int], str]
    monitoring: Callable[[dict[str, Any], str, int | None, dict[str, str | None]], str]


# OpenAI tool schemas. Read-only / supervised-safe only: pause and activate are intentionally
# absent — they stay behind the ADR-0007 human-confirmation button and must never be LLM-callable.
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "scan_flow",
            "description": "Run a read-only analysis of one flow's current health and latest run.",
            "parameters": {
                "type": "object",
                "properties": {"flow_id": {"type": "integer", "description": "The flow's numeric ID."}},
                "required": ["flow_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_org",
            "description": "Scan the whole org for anomalies (the read-only monitoring tick).",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_flow_runs",
            "description": "List the latest runs of one flow (run id, status, records, errors).",
            "parameters": {
                "type": "object",
                "properties": {
                    "flow_id": {"type": "integer", "description": "The flow's numeric ID."},
                    "limit": {"type": "integer", "description": "How many recent runs (default 10)."},
                },
                "required": ["flow_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "manage_monitoring",
            "description": "Register, remove, or list continuously monitored flows for this channel.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["register", "remove", "list"]},
                    "flow_id": {"type": "integer", "description": "Required for register/remove."},
                },
                "required": ["action"],
            },
        },
    },
]


def _req_int(args: dict[str, Any], key: str) -> int:
    value = args.get(key)
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise RouterArgumentError(f"Missing or invalid '{key}'")
    if parsed <= 0:
        raise RouterArgumentError(f"'{key}' must be positive")
    return parsed


def build_catalog(
    context: RouterContext, callbacks: RouterCallbacks
) -> tuple[list[dict[str, Any]], dict[str, Callable[[dict[str, Any]], str]]]:
    """Return (schemas, handlers). Each handler runs one behavior and returns reply text."""

    def scan_flow(args: dict[str, Any]) -> str:
        return callbacks.scan_flow(context.config, _req_int(args, "flow_id"))

    def scan_org(_: dict[str, Any]) -> str:
        callbacks.scan_org(context.config)
        return "Scan finished; any anomalies were printed above."

    def list_flow_runs(args: dict[str, Any]) -> str:
        limit = args.get("limit")
        return callbacks.latest_runs(context.config, _req_int(args, "flow_id"), int(limit) if limit else 10)

    def manage_monitoring(args: dict[str, Any]) -> str:
        action = str(args.get("action") or "").strip().lower()
        if action not in {"register", "remove", "list"}:
            raise RouterArgumentError("action must be register, remove, or list")
        flow_id = args.get("flow_id")
        metadata = {"channel_id": context.channel_id, "user_id": context.user_id}
        return callbacks.monitoring(context.config, action, int(flow_id) if flow_id is not None else None, metadata)

    handlers = {
        "scan_flow": scan_flow,
        "scan_org": scan_org,
        "list_flow_runs": list_flow_runs,
        "manage_monitoring": manage_monitoring,
    }
    return TOOL_SCHEMAS, handlers
