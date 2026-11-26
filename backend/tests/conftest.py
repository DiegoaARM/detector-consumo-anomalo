from __future__ import annotations

import pytest

from backend.app import config, events, store


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    """Keep tests away from the real data/ directory of the developer's PC."""
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "analyses.db")
    monkeypatch.setattr(config, "EVENTS_PATH", tmp_path / "events.jsonl")
    # store/events captured these values at import time, so patch their references too.
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "analyses.db")
    monkeypatch.setattr(events, "EVENTS_PATH", tmp_path / "events.jsonl")
