from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone

from . import config
from .config import DB_PATH, ensure_data_dir
from .schemas import AnalysisResult, Sample

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    source TEXT NOT NULL,
    scenario TEXT NOT NULL,
    label TEXT NOT NULL,
    score REAL NOT NULL,
    confidence REAL NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT NOT NULL,
    source TEXT NOT NULL,
    ts TEXT NOT NULL,
    cpu REAL NOT NULL,
    memory REAL NOT NULL,
    net_out_rate REAL NOT NULL,
    process_count INTEGER NOT NULL,
    top_processes TEXT NOT NULL,
    external_ips TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE INDEX IF NOT EXISTS idx_samples_owner ON samples(owner_id);
"""


def _connect() -> sqlite3.Connection:
    ensure_data_dir()
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    return connection


def save(result: AnalysisResult, samples: list[Sample] | None = None) -> None:
    with closing(_connect()) as connection:
        with connection:
            connection.execute(
                "INSERT INTO analyses (id, created_at, source, scenario, label, score, confidence, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    result.id,
                    result.created_at.isoformat(),
                    result.source,
                    result.scenario,
                    result.label,
                    result.anomaly_score,
                    result.confidence,
                    result.model_dump_json(),
                ),
            )
    if samples:
        save_samples(result.id, result.source, samples)


def save_samples(owner_id: str, source: str, samples: list[Sample]) -> None:
    """Persist raw telemetry points for historical comparison (local/monitor only)."""
    rows = [
        (
            owner_id,
            source,
            sample.ts.isoformat(),
            sample.cpu,
            sample.memory,
            sample.net_out_rate,
            sample.process_count,
            json.dumps(sample.top_processes),
            json.dumps(sample.external_ips),
        )
        for sample in samples
    ]
    with closing(_connect()) as connection:
        with connection:
            connection.executemany(
                "INSERT INTO samples (owner_id, source, ts, cpu, memory, net_out_rate, "
                "process_count, top_processes, external_ips) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(len(ordered) * fraction) - 1))
    return round(ordered[index], 2)


def baseline_stats(
    days: int = config.HISTORY_DAYS,
    exclude_owner_id: str | None = None,
    current_cpu: float | None = None,
    current_net: float | None = None,
) -> dict:
    """Percentiles of prior local/monitor samples, excluding the current analysis."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT cpu, net_out_rate, process_count FROM samples "
            "WHERE ts >= ? AND (? IS NULL OR owner_id != ?)",
            (since, exclude_owner_id, exclude_owner_id),
        ).fetchall()

    cpus = [float(row["cpu"]) for row in rows]
    nets = [float(row["net_out_rate"]) for row in rows]
    processes = [float(row["process_count"]) for row in rows]
    cpu_p95 = _percentile(cpus, 0.95)
    net_p95 = _percentile(nets, 0.95)
    from .features import pct_change  # local import avoids store/features coupling at import time

    return {
        "used": len(rows) >= config.MIN_HISTORY_SAMPLES,
        "sample_count": len(rows),
        "window_days": days,
        "cpu_p95": cpu_p95,
        "net_out_p95": net_p95,
        "process_count_mean": round(sum(processes) / len(processes), 1) if processes else 0.0,
        "cpu_vs_p95_pct": pct_change(cpu_p95, current_cpu if current_cpu is not None else (cpus[-1] if cpus else 0.0)),
        "net_vs_p95_pct": pct_change(net_p95, current_net if current_net is not None else (nets[-1] if nets else 0.0)),
        "note": (
            f"{len(rows)} muestras en {days} días; p95 CPU {cpu_p95:.1f}% y red {net_p95:.0f} B/s."
            if len(rows) >= config.MIN_HISTORY_SAMPLES
            else (
                f"Solo {len(rows)} muestra histórica; hacen falta {config.MIN_HISTORY_SAMPLES} para usar el p95."
                if len(rows) == 1
                else f"Solo {len(rows)} muestras históricas; hacen falta {config.MIN_HISTORY_SAMPLES} para usar el p95."
            )
        ),
    }


def purge_scenarios() -> int:
    """Remove synthetic demo records; only real local scans belong in the DB."""
    with closing(_connect()) as connection:
        with connection:
            cursor = connection.execute("DELETE FROM analyses WHERE source = 'scenario'")
            return cursor.rowcount


def recent(limit: int = 10) -> list[dict]:
    limit = max(1, min(limit, 100))
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT id, created_at, source, scenario, label, score, confidence, payload "
            "FROM analyses ORDER BY created_at DESC, rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
    output = []
    for row in rows:
        payload = json.loads(row["payload"])
        output.append(
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "source": row["source"],
                "scenario": row["scenario"],
                "profile": payload.get("profile", config.DEFAULT_PROFILE),
                "label": row["label"],
                "label_es": payload.get("label_es", row["label"]),
                "score": row["score"],
                "confidence": row["confidence"],
                "headline": payload.get("headline", ""),
            }
        )
    return output
