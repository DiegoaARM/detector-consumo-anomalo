from __future__ import annotations

from dataclasses import dataclass, field

from . import config
from .features import Features
from .schemas import Label, Severity


@dataclass
class Verdict:
    label: Label
    label_es: str
    severity: Severity
    confidence: float
    evidence_legitimate: list[str] = field(default_factory=list)
    evidence_suspicious: list[str] = field(default_factory=list)
    verifications: list[str] = field(default_factory=list)
    context_notes: list[str] = field(default_factory=list)


LABELS_ES: dict[str, str] = {
    "normal": "Comportamiento normal",
    "legitimate_growth": "Crecimiento legítimo probable",
    "suspicious": "Indicios de uso indebido",
    "inconclusive": "Sin conclusión — requiere más contexto",
}

CAVEAT = (
    "Este análisis no confirma minería ilícita ni ninguna actividad maliciosa. "
    "Describe indicios basados en correlación entre señales y requiere verificación humana."
)


def _classify_core(f: Features, score: float, profile_name: str) -> Verdict:
    cfg = config.PROFILES.get(profile_name, config.PROFILES[config.DEFAULT_PROFILE])
    history = f.history or {}
    history_high = bool(history.get("used")) and (
        history.get("cpu_vs_p95_pct", 0.0) >= 20
        or history.get("net_vs_p95_pct", 0.0) >= 50
    )
    cpu_up = f.cpu_delta_pct >= cfg["cpu_delta_pct"] or history_high
    net_up = f.net_out_delta_pct >= cfg["net_delta_pct"] or (
        history_high and f.net_out_delta_pct >= 20
    )
    proc_up = f.process_delta >= 3
    new_proc = bool(f.new_high_cpu_processes)
    external = f.external_ip_delta >= 1
    persistence = bool(f.new_run_keys) or f.scheduled_task_delta >= 1
    explained = bool(f.explaining_events)
    heavy_egress = (
        f.net_out_delta_pct >= cfg["heavy_egress_pct"]
        and f.external_ip_delta >= cfg["min_external_ips"]
    )
    risky_process = bool(f.risky_processes)

    # 1) Several independent suspicious signals, and nothing that explains them.
    if cpu_up and not explained and (
        (new_proc and (external or persistence or risky_process)) or heavy_egress
    ):
        corroborations = sum([new_proc, external, persistence, net_up, risky_process])
        proc_detail = []
        for process in f.new_processes[:2]:
            parts = [f"{process.name} (PID {process.pid})"]
            if process.parent:
                parts.append(f"padre {process.parent}")
            if process.flags:
                parts.append(", ".join(process.flags[:2]))
            proc_detail.append(" · ".join(parts))
        proc_txt = "; ".join(proc_detail) or ", ".join(f.new_high_cpu_processes[:2]) or "proceso nuevo"
        ips_txt = "; ".join(
            f"{ip} → {owner}" for ip, owner in list(f.ip_attribution.items())[:2]
        ) or ", ".join(f.new_external_ips[:2]) or "destino externo nuevo"
        persistence_txt = "; ".join(
            f"{item.kind} '{item.name}'" + (f" → {item.value}" if item.value else "")
            for item in f.persistence_findings[:2]
        )
        return Verdict(
            label="suspicious",
            label_es=LABELS_ES["suspicious"],
            severity="high",
            confidence=round(min(0.93, 0.72 + 0.05 * corroborations), 3),
            evidence_legitimate=[
                "No hay ningún evento de deploy, backup o tarea programada que explique el cambio en la ventana analizada."
            ],
            evidence_suspicious=[
                f"Proceso con consumo alto no presente en la línea base: {proc_txt}.",
                f"Destinos públicos nuevos y su propietario: {ips_txt}.",
                *([f"Persistencia nueva detectada: {persistence_txt}."] if persistence_txt else []),
                f"Tráfico saliente {f.net_out_delta_pct:+.0f}% respecto a la línea base.",
            ],
            verifications=[
                "Confirmar con el dueño del equipo si instaló o ejecutó software nuevo en la ventana.",
                "Inspeccionar la línea de comandos y el proceso padre del PID indicado (sin terminarlo aún).",
                "Verificar el destino externo atribuido contra la política de red.",
                "Revisar la persistencia listada y su fecha de creación.",
                "Si no hay explicación, aislar el equipo de la red y capturar evidencia antes de remediar.",
            ],
        )

    # 2) A CPU jump that matches a declared activity and no suspicious side signals.
    if cpu_up and not external and not persistence and explained:
        event = f.explaining_events[0]
        process_txt = "; ".join(
            f"{p.name} (PID {p.pid}, padre {p.parent or 'desconocido'})"
            for p in f.new_processes[:2]
        )
        return Verdict(
            label="legitimate_growth",
            label_es=LABELS_ES["legitimate_growth"],
            severity="low",
            confidence=round(min(0.92, 0.74 + 0.05 * bool(net_up) + 0.05 * bool(proc_up)), 3),
            evidence_legitimate=[
                f"Evento registrado en la ventana: '{event.type}' {'- ' + event.detail if event.detail else ''}.",
                "No aparecieron destinos externos nuevos.",
                "No cambiaron los mecanismos de inicio automático ni las tareas programadas.",
                *([f"Procesos con más carga: {process_txt}."] if process_txt else []),
                *(
                    [f"Aumento de red saliente ({f.net_out_delta_pct:+.0f}%) coherente con la actividad."]
                    if net_up
                    else []
                ),
                *(
                    [f"Aumento de procesos ({f.process_delta:+d}) coherente con más workers/hilos."]
                    if proc_up
                    else []
                ),
            ],
            evidence_suspicious=[
                f"La CPU subió {f.cpu_delta_pct:+.0f}%; conviene confirmar que el evento cubre toda la ventana."
            ],
            verifications=[
                f"Confirmar el evento '{event.type}' en el sistema de despliegues o bitácora interna.",
                "Comparar latencia/errores antes de cerrar el incidente: el crecimiento debe traducirse en trabajo útil.",
                "Verificar que los procesos con más CPU pertenecen al servicio desplegado.",
                "Revisar el costo proyectado de este nivel de uso con el dueño del presupuesto.",
            ],
        )

    # 3) Broad growth in compute + traffic + workers, with no abuse side signals.
    if cpu_up and not external and not persistence and net_up and proc_up:
        return Verdict(
            label="legitimate_growth",
            label_es=LABELS_ES["legitimate_growth"],
            severity="low",
            confidence=round(min(0.88, 0.72 + 0.05 * (net_up + proc_up)), 3),
            evidence_legitimate=[
                "CPU, red saliente y número de procesos suben juntos: patrón típico de más carga de trabajo.",
                "No aparecieron destinos externos nuevos.",
                "No hay cambios en persistencia ni tareas programadas.",
            ],
            evidence_suspicious=[
                "No hay un evento declarado que explique el aumento; la atribución es probabilística."
            ],
            verifications=[
                "Correlacionar con tráfico entrante, colas o releases recientes.",
                "Confirmar que el incremento de red corresponde a endpoints esperados.",
                "Revisar la factura/cloud billing antes de clasificarlo como incidente de seguridad.",
            ],
        )

    # 4) Score elevated but no corroboration: do not guess.
    if score >= 0.35 or cpu_up:
        return Verdict(
            label="inconclusive",
            label_es=LABELS_ES["inconclusive"],
            severity="medium",
            confidence=round(min(0.68, 0.52 + 0.1 * cpu_up + 0.05 * net_up), 3),
            evidence_legitimate=[
                (
                    f"Hay {f.external_ip_delta} IPs públicas nuevas, pero no están ligadas a un "
                    "proceso nuevo dominante ni a persistencia; patrón común de navegación/CDN."
                    if external
                    else "No se observan destinos externos nuevos ni cambios de persistencia."
                ),
                (
                    "Proceso nuevo con mayor CPU: " + f.new_processes[0].name
                    if f.new_processes
                    else "No aparece un proceso nuevo dominante en la ventana analizada."
                ),
            ],
            evidence_suspicious=[
                f"Desviación de CPU {f.cpu_delta_pct:+.0f}% sin una causa confirmada.",
                (
                    "Proceso con señales a revisar: " + ", ".join(f.risky_processes[:2])
                    if f.risky_processes
                    else "No hay señales de ofuscación o persistencia en los procesos observados."
                ),
            ],
            verifications=[
                "Ampliar la observación a 15 minutos y comparar con la misma hora de la semana pasada.",
                "Revisar si hay un job programado, backup o despliegue no registrado.",
                (
                    "Inspeccionar el PID " + str(f.new_processes[0].pid) + " y su padre "
                    + (f.new_processes[0].parent or "desconocido") + "."
                    if f.new_processes
                    else "Comprobar uso sostenido de CPU, temperatura y métricas de negocio antes de escalar."
                ),
            ],
        )

    # 4b) Many unexplained connections/processes without a CPU jump: do not call it normal.
    unexplained_external = f.external_ip_delta >= 20
    unexplained_processes = len(f.new_processes) >= 3
    if unexplained_external or unexplained_processes:
        owner = next(
            (value for value in f.ip_attribution.values() if value and "no atribuido" not in value),
            "sin atribución a un proceso observado",
        )
        process_names = ", ".join(p.name for p in f.new_processes[:3]) or "ninguno"
        return Verdict(
            label="inconclusive",
            label_es=LABELS_ES["inconclusive"],
            severity="medium",
            confidence=0.55,
            evidence_legitimate=[
                "CPU y red no superan los umbrales del perfil: no hay base para afirmar abuso.",
                "Las IPs nuevas no están ligadas a persistencia ni a un proceso nuevo dominante; "
                "patrón compatible con navegación/CDN."
                if unexplained_external and not risky_process
                else "No hay señales de ofuscación en los procesos observados.",
            ],
            evidence_suspicious=[
                *(
                    [f"{f.external_ip_delta} IPs públicas nuevas; propietario observado: {owner}."]
                    if unexplained_external else []
                ),
                *(
                    [f"{len(f.new_processes)} procesos nuevos con CPU o conexiones: {process_names}."]
                    if unexplained_processes else []
                ),
            ],
            verifications=[
                "Confirmar que las IPs nuevas corresponden a navegación, CDN o servicios esperados.",
                "Verificar el dueño de cada conexión con el propietario del equipo antes de escalar.",
                "Repetir la observación y registrar una actividad si el cambio estaba previsto.",
            ],
        )

    return Verdict(
        label="normal",
        label_es=LABELS_ES["normal"],
        severity="info",
        confidence=round(min(0.96, 0.84 + 0.1 * (score < 0.2)), 3),
        evidence_legitimate=[
            "Las desviaciones de CPU, memoria y red están dentro de la línea base observada.",
            (
                "No hay destinos externos nuevos."
                if f.external_ip_delta == 0
                else f"Solo {f.external_ip_delta} destino(s) público(s) nuevo(s), sin señales de abuso."
            ),
            (
                "No hay procesos nuevos relevantes."
                if not f.new_processes
                else f"{len(f.new_processes)} proceso(s) nuevo(s) sin señales fuertes."
            ),
            (
                "No hay cambios de persistencia."
                if not persistence
                else "Hay persistencia nueva, pero no está correlacionada con CPU o red anómala."
            ),
        ],
        evidence_suspicious=[],
        verifications=[
            "Mantener la línea base actual para futuras comparaciones.",
            "Registrar cambios de software o tareas programadas para mejorar el contexto.",
        ],
    )


def classify(f: Features, score: float, profile_name: str = config.DEFAULT_PROFILE) -> Verdict:
    """Classify with the active profile and attach the context that was used."""
    verdict = _classify_core(f, score, profile_name)
    cfg = config.PROFILES.get(profile_name, config.PROFILES[config.DEFAULT_PROFILE])
    history = f.history or {}
    notes = [
        f"Perfil '{cfg['label']}': umbral CPU {cfg['cpu_delta_pct']:+.0f}% y red "
        f"{cfg['net_delta_pct']:+.0f}% ({cfg['description']})"
    ]
    samples = history.get("sample_count", 0)
    unit = "muestra" if samples == 1 else "muestras"
    if history.get("used"):
        notes.append(
            f"Línea base histórica: {samples} {unit} en "
            f"{history['window_days']} días · p95 CPU {history['cpu_p95']:.1f}% "
            f"(actual {f.current_cpu:.1f}%, {history['cpu_vs_p95_pct']:+.0f}%)."
        )
    else:
        notes.append(
            f"Historial insuficiente ({samples} {unit}): "
            "la comparación usa solo la ventana observada."
        )
    if f.expected_processes:
        notes.append(
            "Procesos declarados como esperados: " + ", ".join(f.expected_processes[:5]) + "."
        )
    expected_findings = [p for p in f.new_processes if p.expected]
    if expected_findings:
        notes.append(
            "Encontrado entre los declarados: "
            + ", ".join(f"{p.name} (PID {p.pid})" for p in expected_findings[:3]) + "."
        )
    if f.new_processes:
        notes.append(
            f"«Nuevos» significa que aparecieron solo en la mitad actual de la ventana "
            f"({len(f.new_processes)}); no prueba que se hayan iniciado ahora."
        )
    verdict.context_notes = notes
    return verdict
