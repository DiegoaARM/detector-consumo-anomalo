from __future__ import annotations

import json
import re
import urllib.request
from typing import Any

from . import config
from .features import Features
from .rules import Verdict


def _rate(value: float) -> str:
    if value >= 1024 * 1024:
        return f"{value / (1024 * 1024):.1f} MB/s"
    if value >= 1024:
        return f"{value / 1024:.1f} KB/s"
    return f"{value:.0f} B/s"


def _clean_text(value: Any, limit: int = 240) -> str:
    return " ".join(str(value).split())[:limit]


_STOPWORDS = {"para", "con", "por", "una", "que", "del", "las", "los", "sin", "más", "una"}


def _content_tokens(text: str) -> set[str]:
    return {
        word
        for word in re.findall(r"[a-záéíóúñü]+", text.lower())
        if len(word) > 3 and word not in _STOPWORDS
    }


_RAW_CHECK_MARKERS = (
    "cpu:", "red:", "memoria:", "procesos nuevos:", "ips nuevas:", "eventos:", "datos:",
)


def _is_usable_check(text: str) -> bool:
    lowered = text.lower()
    return len(text) >= 18 and not any(marker in lowered for marker in _RAW_CHECK_MARKERS)


def _deterministic_reading(f: Features, verdict: Verdict) -> str:
    if verdict.label == "suspicious":
        return (
            "CPU y red suben a la vez y aparecen proceso nuevo, destino externo y persistencia "
            "sin evento declarado; es una pista a verificar, no una prueba."
        )
    if verdict.label == "legitimate_growth":
        return (
            "El cambio coincide con la actividad declarada, por lo que encaja con crecimiento "
            "esperado y no con un patrón de abuso."
        )
    if verdict.label == "inconclusive":
        return (
            "Las señales no bastan para decidir; ampliar la observación y registrar contexto "
            "reduce el riesgo de falsos positivos."
        )
    return (
        "Las métricas se mantienen cerca de la línea base y no aparecen señales fuertes "
        "que requieran escalado."
    )


def build_explanation(
    f: Features, verdict: Verdict, score: float, note: str | None = None
) -> dict[str, Any]:
    headline = f"{verdict.label_es} — confianza {verdict.confidence:.0%}"

    if verdict.label == "suspicious":
        summary = (
            f"CPU {f.baseline_cpu:.1f}% → {f.current_cpu:.1f}% ({f.cpu_delta_pct:+.0f}%), "
            f"memoria {f.baseline_memory:.1f}% → {f.current_memory:.1f}% "
            f"({f.memory_delta_pct:+.0f}%) "
            f"y red saliente {_rate(f.baseline_net_out)} → {_rate(f.current_net_out)} "
            f"({f.net_out_delta_pct:+.0f}%). "
            "La simultaneidad de proceso nuevo, destino externo y cambio de persistencia "
            "sin una actividad declarada amerita verificación. No es una confirmación de minería."
        )
    elif verdict.label == "legitimate_growth":
        summary = (
            f"CPU {f.baseline_cpu:.1f}% → {f.current_cpu:.1f}% ({f.cpu_delta_pct:+.0f}%), "
            f"memoria {f.baseline_memory:.1f}% → {f.current_memory:.1f}% "
            f"({f.memory_delta_pct:+.0f}%) y red saliente "
            f"{_rate(f.baseline_net_out)} → {_rate(f.current_net_out)} "
            f"({f.net_out_delta_pct:+.0f}%). "
            "La desviación es coherente con la actividad registrada y no aparecen señales "
            "de abuso (destinos nuevos o persistencia)."
        )
    elif verdict.label == "inconclusive":
        summary = (
            f"CPU {f.baseline_cpu:.1f}% → {f.current_cpu:.1f}% ({f.cpu_delta_pct:+.0f}%), "
            f"memoria {f.baseline_memory:.1f}% → {f.current_memory:.1f}% "
            f"({f.memory_delta_pct:+.0f}%) y red saliente "
            f"{_rate(f.baseline_net_out)} → {_rate(f.current_net_out)} "
            f"({f.net_out_delta_pct:+.0f}%). "
            "No hay señales claras de abuso ni evento que lo explique. "
            "Clasificar ahora como legítimo o indebido sería especular; conviene ampliar la ventana."
        )
    else:
        summary = (
            f"CPU {f.baseline_cpu:.1f}% → {f.current_cpu:.1f}% ({f.cpu_delta_pct:+.0f}%), "
            f"memoria {f.baseline_memory:.1f}% → {f.current_memory:.1f}% "
            f"({f.memory_delta_pct:+.0f}%) y red saliente "
            f"{_rate(f.baseline_net_out)} → {_rate(f.current_net_out)} "
            f"({f.net_out_delta_pct:+.0f}%). "
            "Las métricas están dentro de la línea base. No se requiere acción."
        )

    if f.new_processes:
        process = f.new_processes[0]
        summary += (
            f" Proceso observado: {_clean_text(process.name, 40)} "
            f"(PID {process.pid}, padre {_clean_text(process.parent or 'desconocido', 40)})."
        )
    if verdict.label in {"suspicious", "inconclusive"} and f.ip_attribution:
        ip, owner = next(iter(f.ip_attribution.items()))
        summary += f" {ip} atribuido a {_clean_text(owner, 60)}."
    if f.history.get("used"):
        summary += (
            f" Frente al histórico de {f.history['sample_count']} muestras, "
            f"la CPU está {f.history['cpu_vs_p95_pct']:+.0f}% respecto al p95 "
            f"({f.history['cpu_p95']:.1f}%)."
        )
    if note:
        summary += f" Nota del analista: {_clean_text(note, 160)}."

    reading = _deterministic_reading(f, verdict)
    summary += f" Lectura: {reading}"

    return {
        "headline": headline,
        "summary": summary,
        "_reading": reading,
        "evidence_legitimate": verdict.evidence_legitimate,
        "evidence_suspicious": verdict.evidence_suspicious,
        "verifications": verdict.verifications,
        "caveat": (
            "No se atribuye minería ilícita basándose solo en un pico de CPU: "
            + verdict.label_es.lower()
            + ". "
            + (
                "La correlación no prueba causalidad y esta conclusión puede cambiar con más contexto."
                if verdict.label == "suspicious"
                else "Se recomienda conservar el registro de la decisión."
            )
        ),
    }


def maybe_enhance_with_llm(explanation: dict[str, Any], f: Features, verdict: Verdict) -> bool:
    """Optionally rewrite prose with a local LLM. Never changes the label or evidence.

    The LLM text is treated as untrusted display data; the frontend renders it as text.
    Returns True when the LLM was used.
    """
    if not config.LLM_URL:
        return False

    base_summary = _clean_text(explanation["summary"], 600)
    base_reading = _clean_text(explanation.get("_reading", ""), 240)
    base_checks = [_clean_text(item, 180) for item in explanation["verifications"][:4]]
    safe_procs = _clean_text(", ".join(f.new_high_cpu_processes[:3]), 80) or "ninguno"
    safe_ips = _clean_text(", ".join(f.new_external_ips[:3]), 80) or "ninguna"
    event_types = [event.type for event in f.explaining_events]
    prompt = (
        "Eres un redactor de contexto, no un clasificador. La categoría ya fue decidida por reglas: "
        f"{verdict.label_es}. No la repitas, no la cambies y no afirmes autoría. "
        f"Lectura determinista verificada que puedes mejorar: {base_reading}. "
        f"Datos exactos: CPU {f.baseline_cpu:.1f}% → {f.current_cpu:.1f}% ({f.cpu_delta_pct:+.0f}%); "
        f"red saliente {_rate(f.baseline_net_out)} → {_rate(f.current_net_out)} ({f.net_out_delta_pct:+.0f}%); "
        f"{len(f.new_processes)} proceso(s) nuevo(s); {f.external_ip_delta} IP(s) pública(s) nueva(s); "
        f"procesos: {safe_procs}; IPs: {safe_ips}; eventos declarados: {event_types}. "
        f"Contexto: {'; '.join(verdict.context_notes[:2])}. "
        f"Verificaciones deterministas: {json.dumps(base_checks, ensure_ascii=False)}. "
        "Reescribe SOLO la lectura en una frase de 40 a 220 caracteres que relacione las señales "
        "sin inventar cifras, sin categorías y sin usar 'velocidad máxima'. "
        "Lectura válida: 'La subida de CPU coincide con el proceso nuevo y el destino externo, sin una actividad declarada que lo explique'. "
        "Lectura inválida: 'Se detectaron indicios de uso indebido'. "
        "Si no puedes mejorarla, deja 'summary' vacío; las verificaciones siguen siendo obligatorias. "
        "El campo 'verifications' debe tener 2 o 3 frases concretas inspiradas en las verificaciones deterministas. "
        "Devuelve solo JSON: {\"summary\": \"...\", \"verifications\": [\"...\", \"...\"]}."
    )
    try:
        payload = json.dumps(
            {
                "model": config.LLM_MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.1, "num_predict": 220},
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            config.LLM_URL.rstrip("/") + "/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=config.LLM_TIMEOUT) as response:
            raw = json.loads(response.read().decode("utf-8"))
        text = raw.get("response", "")
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            return False
        parsed = json.loads(text[start : end + 1])
        reading = _clean_text(parsed.get("summary", ""), 240)
        if reading.lower().startswith("lectura:"):
            reading = reading.split(":", 1)[1].strip()
        checks = [
            _clean_text(c, 180)
            for c in parsed.get("verifications", [])
            if c and _is_usable_check(_clean_text(c, 180))
        ]
        if len(checks) < 2:
            return False
        signal_terms = (
            "cpu", "red", "proceso", "ip", "persistencia", "actividad",
            "evento", "navegación", "cdn", "desviación", "línea base",
        )
        good_reading = (
            len(reading) >= 40
            and "velocidad máxima" not in reading.lower()
            and any(term in reading.lower() for term in signal_terms)
            and len(_content_tokens(reading) & _content_tokens(base_reading)) >= 2
        )
        if good_reading and base_reading:
            explanation["summary"] = base_summary.replace(
                f"Lectura: {base_reading}", f"Lectura: {reading.rstrip('.')}."
            )
        explanation["verifications"] = checks[:5]
        return True
    except Exception:
        return False
