from __future__ import annotations

import re
from dataclasses import dataclass

# A bare run of digits anywhere in the sentence is read as the Flow ID
# ("scan the flow 1234", "look at 1234?"). Capped so a stray long number
# (a timestamp pasted in) does not masquerade as a Flow ID.
_FLOW_ID = re.compile(r"\b(\d{1,18})\b")

# Verb *stems* that mean "go look at a flow", matched as a prefix of a whole word
# so conjugations are covered (analy → analyze/analyse/analysis) without false
# hits inside unrelated words (block does not start with "look"). Kept
# deterministic on purpose: code maps words to an intent, the LLM only explains
# the result (ADR-0002).
_SCAN_STEMS = (
    "scan", "chec", "inspec", "analy", "look", "review", "audit", "examin",
    "diagnos", "verif",
)
_QUIT_WORDS = {"quit", "exit", "q", "bye"}
_HELP_WORDS = {"help", "?", "h", "commands"}


@dataclass(frozen=True)
class Intent:
    """A request parsed from free text. ``flow_id`` is None for a whole-org scan."""

    action: str  # "scan" | "help" | "quit" | "unknown"
    flow_id: int | None = None


def parse_intent(text: str) -> Intent:
    """Map a plain-English request to an Intent. Never raises; unknown text is ``unknown``."""
    low = text.strip().lower()
    if not low:
        return Intent("unknown")
    if low in _QUIT_WORDS:
        return Intent("quit")
    if low in _HELP_WORDS:
        return Intent("help")
    tokens = re.findall(r"[a-z0-9]+", low)
    if any(token.startswith(stem) for token in tokens for stem in _SCAN_STEMS):
        match = _FLOW_ID.search(text)
        flow_id = int(match.group(1)) if match else None
        if flow_id is not None and flow_id <= 0:
            flow_id = None
        return Intent("scan", flow_id)
    return Intent("unknown")
