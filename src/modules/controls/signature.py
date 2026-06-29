from __future__ import annotations

import hmac
import time
from hashlib import sha256


def verify_slack_signature(raw_body: bytes, timestamp: str, signature: str, signing_secret: str, now: float | None = None) -> bool:
    if not signing_secret:
        return False
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    now = time.time() if now is None else now
    if abs(now - ts) > 300:
        return False
    base = b"v0:" + str(ts).encode() + b":" + raw_body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")
