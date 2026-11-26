from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from .schemas import (
    ActivityEvent,
    PersistenceFinding,
    ProcessFinding,
    ProcessInfo,
    Sample,
    Signal,
)

EXPLAINING_TYPES = {"deploy", "backup", "render", "job", "index", "import", "test", "maintenance"}
SHELL_PARENTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh", "conhost.exe"}
TEMP_MARKERS = ("\\temp\\", "/tmp/", "appdata\\local\\temp")
OBFUSCATION_MARKERS = ("-enc ", "base64", "fromcharcode", "chr(", "invoke-expression", "iex ")


def pct_change(baseline: float, current: float, cap: float = 1000.0) -> float:
    """Percentage change with a sane limit when the baseline is zero."""
    if baseline < 1e-6:
        return cap if current > 1e-6 else 0.0
    value = (current - baseline) / baseline * 100.0
    return round(max(-cap, min(cap, value)), 2)


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _flags(process: ProcessInfo) -> list[str]:
    blob = f"{process.exe} {process.cmdline}".lower()
    result = []
    if any(marker in blob for marker in TEMP_MARKERS):
        result.append("ejecutable en directorio temporal")
    if any(marker in blob for marker in OBFUSCATION_MARKERS):
        result.append("línea de comandos ofuscada")
    if process.parent_name.lower() in SHELL_PARENTS:
        result.append("lanzado por shell")
    if process.external_ips:
        result.append("conexión saliente")
    return result


@dataclass
class Features:
    baseline_cpu: float
    current_cpu: float
    baseline_memory: float
    current_memory: float
    baseline_net_out: float
    current_net_out: float
    cpu_delta_pct: float
    memory_delta_pct: float
    net_out_delta_pct: float
    baseline_process_count: int
    current_process_count: int
    process_delta: int
    new_high_cpu_processes: list[str]
    external_ip_delta: int
    new_external_ips: list[str]
    new_run_keys: list[str]
    scheduled_task_delta: int
    new_processes: list[ProcessFinding] = field(default_factory=list)
    persistence_findings: list[PersistenceFinding] = field(default_factory=list)
    ip_attribution: dict[str, str] = field(default_factory=dict)
    risky_processes: list[str] = field(default_factory=list)
    activity_events: list[ActivityEvent] = field(default_factory=list)
    expected_processes: list[str] = field(default_factory=list)
    history: dict = field(default_factory=dict)

    @property
    def explaining_events(self) -> list[ActivityEvent]:
        return [event for event in self.activity_events if event.type.lower() in EXPLAINING_TYPES]

    def signals(self) -> list[Signal]:
        result = [
            Signal(name="cpu", label="CPU", baseline=self.baseline_cpu,
                   current=self.current_cpu, delta_pct=self.cpu_delta_pct),
            Signal(name="memory", label="Memoria", baseline=self.baseline_memory,
                   current=self.current_memory, delta_pct=self.memory_delta_pct),
            Signal(name="net_out", label="Red saliente", baseline=self.baseline_net_out,
                   current=self.current_net_out, delta_pct=self.net_out_delta_pct),
            Signal(name="processes", label="Procesos", baseline=float(self.baseline_process_count),
                   current=float(self.current_process_count),
                   delta_pct=pct_change(float(self.baseline_process_count), float(self.current_process_count))),
            Signal(name="new_processes", label="Procesos nuevos", baseline=0.0,
                   current=float(len(self.new_processes)), delta_pct=float(len(self.new_processes)), unit=""),
            Signal(name="external_ips", label="IPs públicas nuevas", baseline=0.0,
                   current=float(self.external_ip_delta), delta_pct=float(self.external_ip_delta), unit=""),
        ]
        if self.history.get("used"):
            result += [
                Signal(name="cpu_history", label="CPU vs p95 histórico",
                       baseline=float(self.history["cpu_p95"]), current=self.current_cpu,
                       delta_pct=float(self.history["cpu_vs_p95_pct"])),
                Signal(name="net_history", label="Red vs p95 histórico",
                       baseline=float(self.history["net_out_p95"]), current=self.current_net_out,
                       delta_pct=float(self.history["net_vs_p95_pct"])),
            ]
        return result


EVENT_LOOKBACK_SECONDS = 300


def _event_overlaps(event: ActivityEvent, window_start, window_end) -> bool:
    start = event.starts_at or event.ts
    end = event.ends_at or event.ts + timedelta(seconds=EVENT_LOOKBACK_SECONDS)
    return start <= window_end and end >= window_start


def build_features(
    samples: list[Sample],
    activity_events: list[ActivityEvent] | None = None,
    split: int | None = None,
    event_lookback_seconds: int = EVENT_LOOKBACK_SECONDS,
    history: dict | None = None,
) -> Features:
    """Split a telemetry window into baseline/current and derive comparable signals."""
    if len(samples) < 2:
        raise ValueError("Se necesitan al menos dos muestras para comparar una línea base")

    split = split if split is not None else max(1, len(samples) // 2)
    split = min(max(1, split), len(samples) - 1)
    baseline, current = samples[:split], samples[split:]

    window_start = samples[0].ts - timedelta(seconds=event_lookback_seconds)
    window_end = samples[-1].ts
    events = sorted(
        (e for e in (activity_events or []) if _event_overlaps(e, window_start, window_end)),
        key=lambda e: e.ts,
    )
    expected = sorted({
        name.lower() for event in events for name in event.expected_processes
    })

    base_cpu = _mean([s.cpu for s in baseline])
    curr_cpu = _mean([s.cpu for s in current])
    base_mem = _mean([s.memory for s in baseline])
    curr_mem = _mean([s.memory for s in current])
    base_net = _mean([s.net_out_rate for s in baseline])
    curr_net = _mean([s.net_out_rate for s in current])

    def top_names(items: list[Sample]) -> dict[str, float]:
        totals: dict[str, float] = {}
        for item in items:
            for name, value in item.top_processes.items():
                totals[name] = totals.get(name, 0.0) + value / len(items)
        return totals

    base_procs = top_names(baseline)
    curr_procs = top_names(current)
    new_procs = sorted(
        name for name, value in curr_procs.items()
        if value >= 8.0 and base_procs.get(name, 0.0) < 2.0 and name.lower() not in expected
    )

    base_pids = {p.pid for s in baseline for p in s.processes}
    base_names = {p.name for s in baseline for p in s.processes}
    current_processes: dict[int, ProcessInfo] = {}
    for sample in current:
        for process in sample.processes:
            existing = current_processes.get(process.pid)
            if existing:
                existing.external_ips = sorted(set(existing.external_ips) | set(process.external_ips))
                existing.cpu = max(existing.cpu, process.cpu)
            else:
                current_processes[process.pid] = process.model_copy(deep=True)

    findings: list[ProcessFinding] = []
    risky: list[str] = []
    for process in sorted(current_processes.values(), key=lambda p: p.cpu, reverse=True):
        if process.cpu < 8.0 and not process.external_ips:
            continue
        if process.pid in base_pids and process.name in base_names:
            continue
        flags = _flags(process)
        is_expected = process.name.lower() in expected
        findings.append(
            ProcessFinding(
                pid=process.pid,
                name=process.name,
                cpu=round(process.cpu, 2),
                exe=process.exe,
                cmdline=process.cmdline,
                parent=process.parent_name,
                external_ips=process.external_ips,
                flags=flags,
                expected=is_expected,
                expected_by=("evento declarado" if is_expected else ""),
            )
        )
        strong = {"ejecutable en directorio temporal", "línea de comandos ofuscada"}
        if is_expected:
            # Declared processes are not risk just for using a shell or network.
            # Strong obfuscation/temp-location flags still need a human check.
            strong_flags = strong.intersection(flags)
            if strong_flags:
                risky.append(process.name)
        elif strong.intersection(flags) or ("lanzado por shell" in flags and process.external_ips):
            risky.append(process.name)
        if len(findings) >= 8:
            break

    base_ips = {ip for s in baseline for ip in s.external_ips}
    curr_ips = {ip for s in current for ip in s.external_ips}
    new_ips = sorted(curr_ips - base_ips)
    attribution: dict[str, str] = {}
    for ip in new_ips:
        owners = [p for p in current_processes.values() if ip in p.external_ips]
        attribution[ip] = (
            ", ".join(f"{p.name} (PID {p.pid})" for p in owners[:2])
            if owners else "no atribuido a un proceso observado"
        )

    base_keys = {name for s in baseline for name in s.run_key_names}
    curr_keys = {name for s in current for name in s.run_key_names}
    new_keys = sorted(curr_keys - base_keys)
    curr_run_values = {k: v for s in current for k, v in s.run_key_values.items()}

    base_task_names = {name for s in baseline for name in s.scheduled_task_names}
    curr_task_names = {name for s in current for name in s.scheduled_task_names}
    new_tasks = sorted(curr_task_names - base_task_names)
    if base_task_names or curr_task_names:
        task_delta = len(new_tasks)
    else:
        task_delta = int(round(
            _mean([float(s.scheduled_task_count) for s in current])
            - _mean([float(s.scheduled_task_count) for s in baseline])
        ))

    persistence = [
        PersistenceFinding(kind="run_key", name=name, value=curr_run_values.get(name, ""))
        for name in new_keys
    ]
    persistence += [
        PersistenceFinding(kind="scheduled_task", name=name) for name in new_tasks
    ]

    return Features(
        baseline_cpu=round(base_cpu, 2),
        current_cpu=round(curr_cpu, 2),
        baseline_memory=round(base_mem, 2),
        current_memory=round(curr_mem, 2),
        baseline_net_out=round(base_net, 2),
        current_net_out=round(curr_net, 2),
        cpu_delta_pct=pct_change(base_cpu, curr_cpu),
        memory_delta_pct=pct_change(base_mem, curr_mem),
        net_out_delta_pct=pct_change(base_net, curr_net),
        baseline_process_count=int(round(_mean([float(s.process_count) for s in baseline]))),
        current_process_count=int(round(_mean([float(s.process_count) for s in current]))),
        process_delta=int(round(
            _mean([float(s.process_count) for s in current])
            - _mean([float(s.process_count) for s in baseline])
        )),
        new_high_cpu_processes=new_procs,
        external_ip_delta=len(new_ips),
        new_external_ips=new_ips,
        new_run_keys=new_keys,
        scheduled_task_delta=task_delta,
        new_processes=findings,
        persistence_findings=persistence,
        ip_attribution=attribution,
        risky_processes=risky,
        activity_events=events,
        expected_processes=expected,
        history=history or {},
    )
