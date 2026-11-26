from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from .config import EVENTS_PATH, ensure_data_dir
from .schemas import ActivityEvent, EventRequest


def _clean_processes(values: list[str]) -> list[str]:
    return sorted({value.strip().lower() for value in values if value.strip()})[:20]


def append_event(request: EventRequest) -> ActivityEvent:
    ensure_data_dir()
    starts_at = request.starts_at or datetime.now(timezone.utc)
    ends_at = request.ends_at or starts_at + timedelta(
        minutes=request.duration_minutes if request.duration_minutes is not None else 5
    )
    event = ActivityEvent(
        ts=starts_at,
        type=request.type.strip().lower(),
        detail=request.detail.strip(),
        starts_at=starts_at,
        ends_at=ends_at,
        expected_processes=_clean_processes(request.expected_processes),
    )
    with EVENTS_PATH.open("a", encoding="utf-8") as handle:
        handle.write(event.model_dump_json() + "\n")
    return event


def read_events(since: datetime) -> list[ActivityEvent]:
    """Read activity whose declared window overlaps the scan; ignore bad lines."""
    if not EVENTS_PATH.exists():
        return []
    events: list[ActivityEvent] = []
    with EVENTS_PATH.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                event = ActivityEvent.model_validate_json(line)
            except Exception:
                continue
            end = event.ends_at or event.ts + timedelta(minutes=5)
            start = event.starts_at or event.ts
            if end >= since and start <= datetime.now(timezone.utc) + timedelta(days=1):
                events.append(event)
    return events
