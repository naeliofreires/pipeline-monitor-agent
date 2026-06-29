from __future__ import annotations

import re

# Nexla error messages and logs may carry connection strings or credentials (the TDD
# calls this out explicitly). We mask the sensitive parts before they reach the console
# Alert or the off-platform LLM payload, while keeping the rest of the error readable.
# See docs/adr/0006-redact-error-text-before-alert-and-llm.md.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # scheme://user:password@host  ->  scheme://***:***@host
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^\s:/@]+:[^\s:/@]+@"), r"\1***:***@"),
    # JDBC connection strings (the whole URL is the connection string)  ->  jdbc:***
    (re.compile(r"(?i)\bjdbc:[^\s\"']+"), "jdbc:***"),
    # key=value secrets: password / pwd / passwd / secret / token / api[_-]key / access[_-]key
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*=\s*[^\s;,&\"']+"
        ),
        r"\1=***",
    ),
)


def redact(text: str | None) -> str | None:
    """Mask credential / connection-string patterns in free-text error content.

    Returns the input unchanged when it is empty or None; otherwise returns a copy with
    embedded credentials, JDBC URLs, and ``password=``-style secrets masked.
    """
    if not text:
        return text
    result = str(text)
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result
