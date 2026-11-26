from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from .config import SCENARIOS
from .schemas import ActivityEvent, Collection, ProcessInfo, Sample

START_IP = "142.250.4.100"
BASE_TASKS = [f"Mantenimiento_{index:02d}" for index in range(1, 13)]


def _fake_processes(tops: dict[str, float], ips: list[str]) -> list[ProcessInfo]:
    """Demo process metadata so the detail panel is populated in synthetic runs too."""
    catalog = {
        "uvicorn": ("C:\\Python312\\Scripts\\uvicorn.exe", "uvicorn backend.app.main:app --host 0.0.0.0", "python.exe"),
        "code": ("C:\\Program Files\\Microsoft VS Code\\Code.exe", "Code.exe --ms-enable-electron-run-as-node", "explorer.exe"),
        "node": ("C:\\Program Files\\nodejs\\node.exe", "node worker.js --release=v2.4", "cmd.exe"),
        "python (script)": (
            "C:\\Users\\demo\\AppData\\Local\\Temp\\worker\\python.exe",
            'python -c "import base64; exec(base64.b64decode(payload))"',
            "cmd.exe",
        ),
    }
    result = []
    for index, (name, cpu) in enumerate(tops.items()):
        exe, cmdline, parent = catalog.get(name, ("", "", ""))
        result.append(
            ProcessInfo(
                pid=1000 + index,
                name=name,
                cpu=round(cpu, 2),
                exe=exe,
                cmdline=cmdline,
                parent_name=parent,
                external_ips=list(ips) if name == "python (script)" else [],
            )
        )
    return result


def _sample(
    ts: datetime,
    cpu: float,
    memory: float,
    net: float,
    procs: int,
    tops: dict[str, float],
    ips: list[str],
    run_keys: list[str],
    tasks: int,
    run_values: dict[str, str] | None = None,
    task_names: list[str] | None = None,
) -> Sample:
    return Sample(
        ts=ts,
        cpu=round(cpu, 2),
        memory=round(memory, 2),
        net_out_rate=round(net, 2),
        net_in_rate=round(net * 0.35, 2),
        disk_write_rate=round(net * 0.02, 2),
        process_count=procs,
        top_processes=tops,
        processes=_fake_processes(tops, ips),
        external_ips=ips,
        run_key_names=run_keys,
        run_key_values=run_values or {},
        scheduled_task_count=tasks,
        scheduled_task_names=task_names if task_names is not None else BASE_TASKS,
    )


def build_scenario(name: str) -> Collection:
    """Deterministic demos: same input always produces the same classification."""
    if name not in SCENARIOS:
        raise ValueError(f"Escenario desconocido: {name}")

    rng = random.Random(20261125)
    now = datetime.now(timezone.utc)
    samples: list[Sample] = []
    events: list[ActivityEvent] = []

    base_keys = ["OneDrive", "Steam Client Service"]
    stable_ips = [START_IP]

    for i in range(10):
        ts = now - timedelta(seconds=9 - i)
        jitter = rng.uniform(-2, 2)

        if name == "normal":
            sample = _sample(
                ts,
                22 + jitter,
                46 + jitter / 2,
                18_000 + rng.uniform(-2_000, 2_000),
                130 + rng.randint(-2, 2),
                {"uvicorn": 9 + jitter, "code": 6 + jitter / 2},
                stable_ips,
                base_keys,
                12,
            )
        elif name == "legit_deploy":
            if i < 5:
                sample = _sample(
                    ts,
                    22 + jitter,
                    46 + jitter / 2,
                    18_000 + rng.uniform(-2_000, 2_000),
                    130 + rng.randint(-2, 2),
                    {"uvicorn": 9 + jitter, "code": 6},
                    stable_ips,
                    base_keys,
                    12,
                )
            else:
                sample = _sample(
                    ts,
                    78 + jitter,
                    58 + jitter / 2,
                    92_000 + rng.uniform(-5_000, 5_000),
                    145 + rng.randint(-2, 2),
                    {"uvicorn": 48 + jitter, "node": 22 + jitter / 2},
                    stable_ips,
                    base_keys,
                    12,
                )
                if i == 5:
                    events.append(
                        ActivityEvent(
                            ts=ts,
                            type="deploy",
                            detail="release v2.4 (nuevos workers)",
                        )
                    )
        elif name == "suspicious_spike":
            if i < 5:
                sample = _sample(
                    ts,
                    19 + jitter,
                    45 + jitter / 2,
                    15_000 + rng.uniform(-2_000, 2_000),
                    128 + rng.randint(-2, 2),
                    {"uvicorn": 8 + jitter, "code": 5},
                    stable_ips,
                    base_keys,
                    12,
                )
            else:
                sample = _sample(
                    ts,
                    91 + jitter,
                    49 + jitter / 2,
                    260_000 + rng.uniform(-8_000, 8_000),
                    133 + rng.randint(-2, 2),
                    {"python (script)": 72 + jitter, "uvicorn": 5},
                    stable_ips + ["45.77.22.19", "185.220.101.7"],
                    base_keys + ["sysupdate"],
                    13,
                    {"sysupdate": "C:\\Users\\demo\\AppData\\Local\\Temp\\worker\\start.bat"},
                    BASE_TASKS + ["SysUpdateCheck"],
                )
        else:  # sustained_load
            if i < 5:
                sample = _sample(
                    ts,
                    45 + jitter,
                    60 + jitter / 2,
                    20_000 + rng.uniform(-2_000, 2_000),
                    132 + rng.randint(-2, 2),
                    {"uvicorn": 28 + jitter, "code": 7},
                    stable_ips,
                    base_keys,
                    12,
                )
            else:
                sample = _sample(
                    ts,
                    68 + jitter,
                    72 + jitter / 2,
                    21_000 + rng.uniform(-2_000, 2_000),
                    133 + rng.randint(-2, 2),
                    {"uvicorn": 44 + jitter, "code": 7},
                    stable_ips,
                    base_keys,
                    12,
                )
        samples.append(sample)

    return Collection(samples=samples, events=events)
