from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Configurable sampling window (seconds). Can be overridden with env vars or the UI.
DEFAULT_BASELINE_SECONDS = int(os.getenv("DETECTOR_BASELINE_SECONDS", "4"))
DEFAULT_WINDOW_SECONDS = int(os.getenv("DETECTOR_WINDOW_SECONDS", "4"))
MIN_SCAN_SECONDS = 2
MAX_SCAN_SECONDS = 300

# Profiles change the explanation thresholds, never the underlying metrics.
DEFAULT_PROFILE = "workstation"
PROFILES = {
    "workstation": {
        "label": "Estación de trabajo",
        "description": "Equipo de usuario: tolerancia media a picos breves.",
        "cpu_delta_pct": 40,
        "net_delta_pct": 100,
        "heavy_egress_pct": 400,
        "min_external_ips": 2,
    },
    "server": {
        "label": "Servidor",
        "description": "Servicio: cualquier cambio sostenido merece más contexto.",
        "cpu_delta_pct": 25,
        "net_delta_pct": 75,
        "heavy_egress_pct": 300,
        "min_external_ips": 2,
    },
    "development": {
        "label": "Desarrollo",
        "description": "Compilaciones y contenedores: umbrales más altos, espera procesos declarados.",
        "cpu_delta_pct": 60,
        "net_delta_pct": 200,
        "heavy_egress_pct": 600,
        "min_external_ips": 3,
    },
}

# Historical baseline (percentiles of stored samples).
HISTORY_DAYS = 14
MIN_HISTORY_SAMPLES = 20
MONITOR_DEFAULT_INTERVAL_SECONDS = int(os.getenv("DETECTOR_MONITOR_INTERVAL", "60"))
MONITOR_DEFAULT_DURATION_MINUTES = int(os.getenv("DETECTOR_MONITOR_MINUTES", "15"))

DATA_DIR = Path(os.getenv("DETECTOR_DATA_DIR", str(ROOT / "data")))
DB_PATH = DATA_DIR / "analyses.db"
EVENTS_PATH = DATA_DIR / "events.jsonl"
FRONT_DIR = ROOT / "frontend"

# Optional local LLM (Ollama by default). Empty means deterministic explanations only.
LLM_URL = os.getenv("DETECTOR_LLM_URL", "").strip()
if LLM_URL.lower() in {"0", "off", "false", "none", "no"}:
    LLM_URL = ""
LLM_MODEL = os.getenv("DETECTOR_LLM_MODEL", "llama3.2:3b")
LLM_TIMEOUT = float(os.getenv("DETECTOR_LLM_TIMEOUT", "30"))

SCENARIOS = ("normal", "legit_deploy", "suspicious_spike", "sustained_load")


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
