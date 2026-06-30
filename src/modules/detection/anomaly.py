from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Anomaly:
    """Internal representation of a detected flow anomaly.

    The shared domain entity every detector produces and every downstream module
    (enrichment, classification, suppression, alerting) consumes.
    """

    notification_id: int
    type: str
    flow_id: int | None
    flow_name: str | None
    level: str | None
    resource_id: int | None
    resource_type: str | None
    message: str
    detected_at: datetime | str | None
    owner_name: str | None = None
    owner_email: str | None = None
    org_name: str | None = None
    access_roles: tuple[str, ...] = ()
    read_at: datetime | str | None = None
    created_at: datetime | str | None = None
    updated_at: datetime | str | None = None
