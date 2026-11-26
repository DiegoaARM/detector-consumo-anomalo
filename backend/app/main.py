from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import config, events, metrics, monitor, store
from .collector import collect_local
from .detector import Detector
from .explain import build_explanation, maybe_enhance_with_llm
from .features import EVENT_LOOKBACK_SECONDS, build_features
from .rules import CAVEAT, classify
from .schemas import AnalysisResult, AnalyzeRequest, EventRequest, HistoryBaseline, MonitorRequest
from .scenarios import build_scenario

STARTED_AT = time.monotonic()
RULES_VERSION = "1.1.0"

config.ensure_data_dir()
config.FRONT_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="Centinela de Consumo",
    description="Detecta desviaciones de recursos, explica el contexto y propone verificaciones.",
    version="0.1.0",
)
app.mount("/app", StaticFiles(directory=config.FRONT_DIR, html=True), name="frontend")
detector = Detector()

# Synthetic demos are never stored. Clean records from earlier versions on startup.
_removed_demos = store.purge_scenarios()
if _removed_demos:
    print(f"[centinela] eliminados {_removed_demos} análisis sintéticos de la BD")


@app.middleware("http")
async def count_requests(request, call_next):
    metrics.count_request(request.url.path)
    return await call_next(request)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/app/index.html")


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "centinela-consumo",
        "version": app.version,
        "uptime_s": round(time.monotonic() - STARTED_AT, 1),
        "model": detector.model_name,
        "rules_version": RULES_VERSION,
        "scenarios": list(config.SCENARIOS),
        "llm_configured": bool(config.LLM_URL),
        "database": config.DB_PATH.name,
        "profile_default": config.DEFAULT_PROFILE,
        "monitor_running": monitor.monitor.status()["running"],
        "scan_defaults": {
            "baseline_seconds": config.DEFAULT_BASELINE_SECONDS,
            "window_seconds": config.DEFAULT_WINDOW_SECONDS,
        },
    }


@app.get("/api/config")
def scan_config() -> dict:
    return {
        "baseline_seconds": config.DEFAULT_BASELINE_SECONDS,
        "window_seconds": config.DEFAULT_WINDOW_SECONDS,
        "min_seconds": config.MIN_SCAN_SECONDS,
        "max_seconds": config.MAX_SCAN_SECONDS,
        "event_lookback_seconds": EVENT_LOOKBACK_SECONDS,
        "default_profile": config.DEFAULT_PROFILE,
        "profiles": config.PROFILES,
        "history_days": config.HISTORY_DAYS,
        "min_history_samples": config.MIN_HISTORY_SAMPLES,
        "monitor_interval_seconds": config.MONITOR_DEFAULT_INTERVAL_SECONDS,
        "monitor_duration_minutes": config.MONITOR_DEFAULT_DURATION_MINUTES,
    }


@app.get("/api/baseline")
def baseline(days: int = Query(default=config.HISTORY_DAYS, ge=1, le=90)) -> dict:
    return store.baseline_stats(days=days)


@app.get("/api/monitor/status")
def monitor_status() -> dict:
    return monitor.monitor.status()


@app.post("/api/monitor/start")
def monitor_start(request: MonitorRequest) -> dict:
    try:
        return monitor.monitor.start(request.interval_seconds, request.duration_minutes)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/monitor/stop")
def monitor_stop() -> dict:
    return monitor.monitor.stop()


@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics() -> str:
    return metrics.render()


@app.get("/api/scenarios")
def list_scenarios() -> list[dict]:
    return [
        {
            "id": "normal",
            "title": "Normal",
            "description": "Línea base estable, sin desviaciones.",
        },
        {
            "id": "legit_deploy",
            "title": "Pico por deploy legítimo",
            "description": "CPU y red suben junto a un release v2.4 registrado.",
        },
        {
            "id": "suspicious_spike",
            "title": "Pico sospechoso",
            "description": "Proceso nuevo, IPs externas y persistencia sin evento que lo explique.",
        },
        {
            "id": "sustained_load",
            "title": "Carga sostenida",
            "description": "CPU alta sin señales de abuso ni causa declarada.",
        },
    ]


@app.post("/api/events", status_code=201)
def register_event(request: EventRequest) -> dict:
    event = events.append_event(request)
    return {"status": "ok", "event": event.model_dump(mode="json")}


@app.post("/api/analyze", response_model=AnalysisResult)
def analyze(request: AnalyzeRequest) -> AnalysisResult:
    analysis_id = uuid.uuid4().hex[:10]
    if request.source == "local":
        collection = collect_local(request.baseline_seconds, request.window_seconds)
        scenario_name = "local_scan"
        activity = events.read_events(
            collection.samples[0].ts - timedelta(seconds=EVENT_LOOKBACK_SECONDS)
        )
        split = max(1, len(collection.samples) // 2)
        recent_samples = collection.samples[split:]
        cur_cpu = sum(s.cpu for s in recent_samples) / len(recent_samples)
        cur_net = sum(s.net_out_rate for s in recent_samples) / len(recent_samples)
        history = store.baseline_stats(
            days=config.HISTORY_DAYS,
            exclude_owner_id=analysis_id,
            current_cpu=cur_cpu,
            current_net=cur_net,
        )
    else:
        scenario_name = request.scenario or "normal"
        if scenario_name not in config.SCENARIOS:
            raise HTTPException(
                status_code=422,
                detail=f"Escenario inválido. Opciones: {', '.join(config.SCENARIOS)}",
            )
        collection = build_scenario(scenario_name)
        activity = collection.events
        history = {}  # demos must not borrow context from the user's real history

    features = build_features(collection.samples, activity, history=history)
    score = detector.score(features)
    verdict = classify(features, score, request.profile)
    if request.source == "scenario":
        verdict.context_notes = [
            note for note in verdict.context_notes
            if not note.startswith("Historial insuficiente")
        ] + ["Escenario sintético: no se consulta el histórico real del equipo."]
    explanation = build_explanation(features, verdict, score, request.note)
    llm_used = maybe_enhance_with_llm(explanation, features, verdict)

    warnings = list(collection.warnings)
    if config.LLM_URL and not llm_used:
        warnings.append("LLM local no disponible; se usó la explicación determinista.")

    result = AnalysisResult(
        id=analysis_id,
        created_at=datetime.now(timezone.utc),
        source=request.source,
        scenario=scenario_name,
        profile=request.profile,
        label=verdict.label,
        label_es=verdict.label_es,
        severity=verdict.severity,
        confidence=verdict.confidence,
        anomaly_score=score,
        headline=explanation["headline"],
        summary=explanation["summary"],
        signals=features.signals(),
        context_notes=verdict.context_notes,
        evidence_legitimate=explanation["evidence_legitimate"],
        evidence_suspicious=explanation["evidence_suspicious"],
        verifications=explanation["verifications"],
        caveat=CAVEAT,
        series=[
            {
                "ts": sample.ts,
                "cpu": sample.cpu,
                "memory": sample.memory,
                "net_out_rate": sample.net_out_rate,
            }
            for sample in collection.samples
        ],
        activity_events=features.activity_events,
        process_findings=features.new_processes,
        persistence_findings=features.persistence_findings,
        history_baseline=HistoryBaseline(**history) if request.source == "local" else None,
        warnings=warnings,
        model=detector.model_name,
        llm_used=llm_used,
        persisted=request.source == "local",
    )

    if result.persisted:
        store.save(result, collection.samples)
    metrics.observe(verdict.label, score)
    return result


@app.get("/api/history")
def history(limit: int = Query(default=8, ge=1, le=100)) -> list[dict]:
    return store.recent(limit)
