from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.app.detector import Detector
from backend.app.features import build_features
from backend.app.rules import CAVEAT, classify
from backend.app.schemas import ActivityEvent, ProcessInfo, Sample
from backend.app import store
from backend.app.scenarios import build_scenario

EXPECTED = {
    "normal": "normal",
    "legit_deploy": "legitimate_growth",
    "suspicious_spike": "suspicious",
    "sustained_load": "inconclusive",
}


@pytest.mark.parametrize("scenario,expected", EXPECTED.items())
def test_scenario_classification(scenario: str, expected: str) -> None:
    collection = build_scenario(scenario)
    features = build_features(collection.samples, collection.events)
    score = Detector().score(features)
    verdict = classify(features, score)
    assert verdict.label == expected, (scenario, verdict.label, score)
    assert verdict.verifications
    assert "no confirma minería" in CAVEAT


def test_cpu_spike_alone_is_not_mining_accusation() -> None:
    """A CPU increase with a declared deploy and no abuse side signals stays legitimate."""
    collection = build_scenario("legit_deploy")
    features = build_features(collection.samples, collection.events)
    verdict = classify(features, Detector().score(features))
    assert verdict.label == "legitimate_growth"
    assert "minería" not in " ".join(verdict.evidence_suspicious).lower()


def test_activity_registered_before_window_counts_as_context() -> None:
    """The analyst logs a deploy first, then scans: it must still be considered."""
    now = datetime.now(timezone.utc)
    samples = [
        Sample(
            ts=now + timedelta(seconds=i),
            cpu=20 if i < 5 else 80,
            memory=45,
            net_out_rate=20_000,
            net_in_rate=5_000,
            disk_write_rate=100,
            process_count=130,
            top_processes={"uvicorn": 10},
        )
        for i in range(10)
    ]
    event = ActivityEvent(ts=now - timedelta(seconds=30), type="deploy", detail="v2.4")
    features = build_features(samples, [event])
    assert features.explaining_events == [event]
    assert classify(features, Detector().score(features)).label == "legitimate_growth"


def test_process_details_flags_and_ip_attribution() -> None:
    """Real process metadata becomes evidence instead of a generic CPU spike."""
    now = datetime.now(timezone.utc)
    samples = []
    for i in range(8):
        current = i >= 4
        samples.append(
            Sample(
                ts=now + timedelta(seconds=i),
                cpu=20 if not current else 85,
                memory=45,
                net_out_rate=10_000 if not current else 200_000,
                net_in_rate=1_000,
                disk_write_rate=100,
                process_count=130,
                top_processes={"chrome": 8} if not current else {"worker": 70},
                processes=[
                    ProcessInfo(
                        pid=10, name="chrome", cpu=8, external_ips=["1.1.1.1"]
                    )
                ] if not current else [
                    ProcessInfo(
                        pid=20,
                        name="worker",
                        cpu=70,
                        exe=r"C:\Users\demo\AppData\Local\Temp\worker.exe",
                        cmdline="python -c base64 payload",
                        parent_name="cmd.exe",
                        external_ips=["45.77.22.19"],
                    )
                ],
                external_ips=["1.1.1.1"] if not current else ["45.77.22.19"],
            )
        )
    features = build_features(samples)
    assert len(features.new_processes) == 1
    finding = features.new_processes[0]
    assert finding.pid == 20
    assert "ejecutable en directorio temporal" in finding.flags
    assert "línea de comandos ofuscada" in finding.flags
    assert "worker" in features.ip_attribution["45.77.22.19"]
    assert "worker" in features.risky_processes


def test_event_window_and_expected_process_reduce_false_positives() -> None:
    """A declared job with expected processes must not be read as an unknown worker."""
    now = datetime.now(timezone.utc)
    samples = []
    for i in range(8):
        current = i >= 4
        samples.append(
            Sample(
                ts=now + timedelta(seconds=i),
                cpu=30 if not current else 70,
                memory=50,
                net_out_rate=10_000,
                net_in_rate=1_000,
                disk_write_rate=100,
                process_count=140,
                top_processes={"chrome": 8} if not current else {"worker": 45},
                processes=[
                    ProcessInfo(
                        pid=10, name="chrome", cpu=8, external_ips=[]
                    )
                ] if not current else [
                    ProcessInfo(
                        pid=20,
                        name="worker",
                        cpu=45,
                        exe=r"C:\Program Files\Worker\worker.exe",
                        cmdline="worker.exe --job=nightly",
                        parent_name="cmd.exe",
                        external_ips=["45.77.22.19"],
                    )
                ],
                external_ips=[] if not current else ["45.77.22.19"],
            )
        )
    event = ActivityEvent(
        ts=now - timedelta(seconds=10),
        type="job",
        detail="nightly",
        starts_at=now - timedelta(seconds=10),
        ends_at=now + timedelta(seconds=60),
        expected_processes=["worker"],
    )
    features = build_features(samples, [event])
    assert features.explaining_events == [event]
    assert features.expected_processes == ["worker"]
    assert features.new_processes[0].expected is True
    assert "worker" not in features.new_high_cpu_processes
    assert "worker" not in features.risky_processes
    # Declared process is not "unknown", but an unexplained external IP still needs review.
    assert classify(features, 0.4).label == "inconclusive"


def test_expired_event_does_not_explain_a_scan() -> None:
    now = datetime.now(timezone.utc)
    samples = [
        Sample(
            ts=now + timedelta(seconds=i),
            cpu=20 if i < 5 else 80,
            memory=45,
            net_out_rate=20_000,
            net_in_rate=5_000,
            disk_write_rate=100,
            process_count=130,
            top_processes={"uvicorn": 10},
        )
        for i in range(10)
    ]
    old = ActivityEvent(
        ts=now - timedelta(seconds=500),
        type="deploy",
        starts_at=now - timedelta(seconds=500),
        ends_at=now - timedelta(seconds=400),
    )
    assert build_features(samples, [old]).explaining_events == []


def test_profile_thresholds_change_classification() -> None:
    """A +30% CPU jump is routine for development, notable for a server."""
    now = datetime.now(timezone.utc)
    samples = []
    for i in range(8):
        current = i >= 4
        samples.append(
            Sample(
                ts=now + timedelta(seconds=i),
                cpu=20 if not current else 26,
                memory=45,
                net_out_rate=10_000,
                net_in_rate=1_000,
                disk_write_rate=100,
                process_count=130,
                top_processes={"chrome": 8} if not current else {"worker": 30},
                processes=[
                    ProcessInfo(pid=10, name="chrome", cpu=8)
                ] if not current else [
                    ProcessInfo(
                        pid=20,
                        name="worker",
                        cpu=30,
                        exe=r"C:\Users\demo\AppData\Local\Temp\worker.exe",
                        cmdline="python -c base64 payload",
                        parent_name="cmd.exe",
                        external_ips=["45.77.22.19"],
                    )
                ],
                external_ips=[] if not current else ["45.77.22.19"],
                run_key_names=[] if not current else ["sysupdate"],
            )
        )
    features = build_features(samples)
    assert classify(features, 0.5, "server").label == "suspicious"
    assert classify(features, 0.5, "development").label == "inconclusive"
    notes = classify(features, 0.5, "server").context_notes
    assert any("Servidor" in note for note in notes)


def test_many_unexplained_connections_are_not_reported_as_normal() -> None:
    """127 new IPs + 7 new processes must not produce 'no new external destinations'."""
    now = datetime.now(timezone.utc)
    ips = [f"45.77.22.{index}" for index in range(25)]
    samples = []
    for i in range(8):
        current = i >= 4
        samples.append(
            Sample(
                ts=now + timedelta(seconds=i),
                cpu=30,
                memory=50,
                net_out_rate=50_000,
                net_in_rate=5_000,
                disk_write_rate=100,
                process_count=200,
                top_processes={"chrome": 8} if not current else {
                    "chrome": 8, "app_a": 9, "app_b": 9, "app_c": 9
                },
                processes=[] if not current else [
                    ProcessInfo(pid=pid, name=name, cpu=9,
                                exe=rf"C:\Program Files\{name}\{name}.exe")
                    for pid, name in ((21, "app_a"), (22, "app_b"), (23, "app_c"))
                ],
                external_ips=[] if not current else ips,
            )
        )
    features = build_features(samples)
    verdict = classify(features, 0.3)
    assert verdict.label == "inconclusive"
    assert features.external_ip_delta == 25
    assert len(features.new_processes) == 3
    assert any("25 IPs públicas nuevas" in item for item in verdict.evidence_suspicious)
    assert not any("No hay destinos externos nuevos" in item for item in verdict.evidence_legitimate)


def test_historical_samples_build_a_p95_baseline() -> None:
    now = datetime.now(timezone.utc)
    samples = [
        Sample(
            ts=now + timedelta(seconds=i),
            cpu=float(10 + i),
            memory=40,
            net_out_rate=float(100 + i),
            net_in_rate=10,
            disk_write_rate=1,
            process_count=120,
        )
        for i in range(25)
    ]
    store.save_samples("test_owner", "monitor", samples)
    stats = store.baseline_stats(days=1, current_cpu=95, current_net=1_000)
    assert stats["sample_count"] == 25
    assert stats["used"] is True
    assert stats["cpu_p95"] >= 30
    assert stats["cpu_vs_p95_pct"] > 0
