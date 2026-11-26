from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from . import store
from .collector import collect_sample


class Monitor:
    """In-process read-only sampler that feeds the historical baseline.

    It never analyses or stores verdicts: it only appends raw telemetry samples
    under a monitor run id, so future scans can compare against a real history.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._status: dict = {
            "running": False,
            "run_id": None,
            "samples": 0,
            "started_at": None,
            "ends_at": None,
            "interval_seconds": 0,
            "duration_minutes": 0,
            "error": None,
        }

    def status(self) -> dict:
        with self._lock:
            return dict(self._status)

    def start(self, interval_seconds: int, duration_minutes: int) -> dict:
        with self._lock:
            if self._status["running"]:
                raise RuntimeError("El monitor ya está en ejecución.")
            self._stop.clear()
            run_id = "mon_" + uuid.uuid4().hex[:8]
            started = datetime.now(timezone.utc)
            self._status = {
                "running": True,
                "run_id": run_id,
                "samples": 0,
                "started_at": started.isoformat(),
                "ends_at": (started + timedelta(minutes=duration_minutes)).isoformat(),
                "interval_seconds": interval_seconds,
                "duration_minutes": duration_minutes,
                "error": None,
            }
            self._thread = threading.Thread(
                target=self._run,
                args=(run_id, interval_seconds, duration_minutes),
                daemon=True,
                name=f"centinela-monitor-{run_id}",
            )
            self._thread.start()
            return dict(self._status)

    def stop(self) -> dict:
        self._stop.set()
        with self._lock:
            self._status["running"] = False
            self._status["ends_at"] = datetime.now(timezone.utc).isoformat()
            return dict(self._status)

    def _run(self, run_id: str, interval_seconds: int, duration_minutes: int) -> None:
        deadline = time.monotonic() + duration_minutes * 60
        while not self._stop.is_set() and time.monotonic() < deadline:
            try:
                sample = collect_sample()
                store.save_samples(run_id, "monitor", [sample])
                with self._lock:
                    self._status["samples"] += 1
            except Exception as exc:  # keep the monitor alive; report the problem
                with self._lock:
                    self._status["error"] = str(exc)[:240]
            if self._stop.wait(interval_seconds):
                break
        with self._lock:
            self._status["running"] = False
            self._status["ends_at"] = datetime.now(timezone.utc).isoformat()


monitor = Monitor()
