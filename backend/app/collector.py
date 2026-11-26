from __future__ import annotations

import ipaddress
import platform
import subprocess
import time
from datetime import datetime, timezone

import psutil

from .schemas import Collection, ProcessInfo, Sample

_MAX_TOP_PROCESSES = 8
_MIN_PROCESS_CPU = 0.5


def _clean(value: object, limit: int = 240) -> str:
    if not value:
        return ""
    return " ".join(str(value).split())[:limit]


def _network_state() -> tuple[list[str], dict[int, list[str]]]:
    """Public ESTABLISHED destinations, plus which PID owns each connection."""
    ips: set[str] = set()
    by_pid: dict[int, set[str]] = {}
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
            continue
        address = conn.raddr.ip
        try:
            if not ipaddress.ip_address(address).is_global:
                continue
        except ValueError:
            continue
        ips.add(address)
        if conn.pid:
            by_pid.setdefault(conn.pid, set()).add(address)
    return sorted(ips), {pid: sorted(values) for pid, values in by_pid.items()}


def _run_keys() -> tuple[list[str], dict[str, str]]:
    """Names and values of HKCU Run entries (local only, never sent anywhere)."""
    names: list[str] = []
    values: dict[str, str] = {}
    if platform.system() != "Windows":
        return names, values
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"
        )
        index = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, index)
                names.append(name)
                values[name] = _clean(value, 200)
                index += 1
            except OSError:
                break
    except Exception:
        pass
    return sorted(names), values


def _scheduled_tasks() -> list[str]:
    if platform.system() != "Windows":
        return []
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/nh"],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=flags,
        )
        names = set()
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            name = line.split(",", 1)[0].strip().strip('"')
            if name and "\\" in name:
                names.add(name.rsplit("\\", 1)[-1])
        return sorted(names)
    except Exception:
        return []


def _process_details(
    candidates: dict[int, float],
    external_by_pid: dict[int, list[str]],
) -> list[ProcessInfo]:
    details: list[ProcessInfo] = []
    for pid, cpu in sorted(candidates.items(), key=lambda item: item[1], reverse=True)[:_MAX_TOP_PROCESSES]:
        try:
            process = psutil.Process(pid)
            data = process.as_dict(
                attrs=["name", "memory_percent", "exe", "cmdline", "ppid", "create_time"],
                ad_value=None,
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            continue

        parent_pid = data.get("ppid")
        parent_name = ""
        if parent_pid:
            try:
                parent_name = _clean(psutil.Process(parent_pid).name(), 60)
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                pass

        created = data.get("create_time")
        details.append(
            ProcessInfo(
                pid=pid,
                name=_clean(data.get("name"), 60) or "<desconocido>",
                cpu=round(cpu, 2),
                memory=round(float(data.get("memory_percent") or 0.0), 2),
                exe=_clean(data.get("exe"), 260),
                cmdline=_clean(" ".join(data.get("cmdline") or []), 240),
                parent_pid=parent_pid,
                parent_name=parent_name,
                created_at=datetime.fromtimestamp(created, tz=timezone.utc) if created else None,
                external_ips=external_by_pid.get(pid, []),
            )
        )
    return details


def collect_sample() -> Sample:
    """One read-only point for the background monitor (1 s of CPU priming)."""
    return collect_local(1, 0).samples[0]


def collect_local(baseline_seconds: int, window_seconds: int) -> Collection:
    """Read local telemetry with psutil. No process is killed and nothing is changed."""
    warnings: list[str] = []
    psutil.cpu_percent(interval=None)  # prime the global CPU counter

    process_cpu: dict[int, float] = {}
    for proc in psutil.process_iter():
        try:
            process_cpu[proc.pid] = proc.cpu_percent()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

    prev_net = psutil.net_io_counters()
    prev_disk = psutil.disk_io_counters()
    prev_ts = time.monotonic()
    task_names = _scheduled_tasks()
    samples: list[Sample] = []
    network_visible = True

    phases = (("baseline", baseline_seconds), ("window", window_seconds))
    for phase_index, (_, seconds) in enumerate(phases):
        for _ in range(seconds):
            time.sleep(1.0)
            now_ts = time.monotonic()
            elapsed = max(0.001, now_ts - prev_ts)
            prev_ts = now_ts

            net = psutil.net_io_counters()
            disk = psutil.disk_io_counters()
            net_out = max(0.0, (net.bytes_sent - prev_net.bytes_sent) / elapsed) if net and prev_net else 0.0
            net_in = max(0.0, (net.bytes_recv - prev_net.bytes_recv) / elapsed) if net and prev_net else 0.0
            disk_write = max(0.0, (disk.write_bytes - prev_disk.write_bytes) / elapsed) if disk and prev_disk else 0.0
            prev_net, prev_disk = net, disk

            candidates: dict[int, float] = {}
            for proc in psutil.process_iter():
                try:
                    value = process_cpu.get(proc.pid)
                    process_cpu[proc.pid] = proc.cpu_percent()
                    if value is None or value < _MIN_PROCESS_CPU:
                        continue
                    candidates[proc.pid] = value
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

            try:
                ips, external_by_pid = _network_state()
            except (psutil.AccessDenied, OSError):
                ips, external_by_pid = [], {}
                network_visible = False

            details = _process_details(candidates, external_by_pid)
            run_names, run_values = _run_keys()

            top: dict[str, float] = {}
            for item in details:
                top[item.name] = round(top.get(item.name, 0.0) + item.cpu, 2)
            top = dict(sorted(top.items(), key=lambda item: item[1], reverse=True)[:_MAX_TOP_PROCESSES])

            if phase_index == 1 and len(samples) == baseline_seconds:
                task_names = _scheduled_tasks()

            samples.append(
                Sample(
                    ts=datetime.now(timezone.utc),
                    cpu=round(psutil.cpu_percent(interval=None), 2),
                    memory=round(psutil.virtual_memory().percent, 2),
                    net_out_rate=round(net_out, 2),
                    net_in_rate=round(net_in, 2),
                    disk_write_rate=round(disk_write, 2),
                    process_count=len(psutil.pids()),
                    top_processes=top,
                    processes=details,
                    external_ips=ips,
                    run_key_names=run_names,
                    run_key_values=run_values,
                    scheduled_task_count=len(task_names),
                    scheduled_task_names=task_names,
                )
            )

    if not network_visible:
        warnings.append(
            "Sin permisos para leer conexiones de red: el análisis no puede atribuir destinos a procesos."
        )
    return Collection(samples=samples, warnings=warnings)
