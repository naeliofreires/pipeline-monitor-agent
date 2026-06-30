from __future__ import annotations

import logging
from typing import Any, Callable, Protocol

from modules.controls.router_tools import RouterArgumentError, RouterCallbacks, RouterContext, build_catalog

logger = logging.getLogger(__name__)


class CommandRouter(Protocol):
    """An LLM adapter that picks one tool for a message (or answers directly)."""

    def route_command(self, message: str, tools: list[dict[str, Any]]) -> dict[str, Any]: ...


def route_message(
    message: str,
    context: RouterContext,
    callbacks: RouterCallbacks,
    llm_adapter: CommandRouter,
    fallback: Callable[[str], str],
) -> str:
    """Ask the LLM which single behavior to run; degrade to the deterministic ``fallback`` on any
    routing problem (LLM unavailable, unknown tool, or unusable arguments). Execution errors from a
    chosen behavior propagate to the caller — retrying them via the fallback would just fail again.
    """
    schemas, handlers = build_catalog(context, callbacks)
    try:
        result = llm_adapter.route_command(message, schemas)
    except Exception:
        logger.warning("LLM routing failed; using deterministic fallback", exc_info=True)
        return fallback(message)

    tool = result.get("tool")
    if tool:
        handler = handlers.get(tool)
        if handler is None:
            logger.info("LLM picked unknown tool %r; using deterministic fallback", tool)
            return fallback(message)
        try:
            return handler(result.get("arguments") or {})
        except RouterArgumentError as exc:
            logger.info("Tool %s had unusable arguments (%s); using deterministic fallback", tool, exc)
            return fallback(message)

    text = (result.get("text") or "").strip()
    return text or fallback(message)
