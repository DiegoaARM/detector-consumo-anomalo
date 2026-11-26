from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_health_reports_model_and_rules() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["model"]
    assert body["rules_version"]
    assert "scan_defaults" in body


def test_config_exposes_scan_limits() -> None:
    body = client.get("/api/config").json()
    assert body["min_seconds"] == 2
    assert body["max_seconds"] >= 60
    assert body["baseline_seconds"] >= body["min_seconds"]
    assert set(body["profiles"]) == {"workstation", "server", "development"}
    assert body["min_history_samples"] >= 1


def test_metrics_expose_service_signals() -> None:
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "detector_analyses_total" in response.text
    assert "detector_last_score" in response.text


def test_analyze_scenario_returns_explanation_without_persisting() -> None:
    response = client.post("/api/analyze", json={"source": "scenario", "scenario": "suspicious_spike"})
    assert response.status_code == 200
    body = response.json()
    assert body["label"] == "suspicious"
    assert body["persisted"] is False
    assert body["evidence_suspicious"]
    assert body["verifications"]
    assert "no confirma minería" in body["caveat"]
    assert body["series"]
    assert client.get("/api/history").json() == []


def test_invalid_scenario_is_rejected() -> None:
    response = client.post("/api/analyze", json={"source": "scenario", "scenario": "nope"})
    assert response.status_code == 422


def test_scan_seconds_are_configurable() -> None:
    response = client.post(
        "/api/analyze",
        json={"source": "local", "baseline_seconds": 2, "window_seconds": 2},
    )
    assert response.status_code == 200
    assert len(response.json()["series"]) == 4


def test_events_and_history_only_store_real_scans() -> None:
    created = client.post("/api/events", json={"type": "deploy", "detail": "v2.4"})
    assert created.status_code == 201

    demo = client.post("/api/analyze", json={"source": "scenario", "scenario": "legit_deploy"})
    assert demo.json()["persisted"] is False
    assert client.get("/api/history").json() == []

    real = client.post(
        "/api/analyze",
        json={"source": "local", "baseline_seconds": 2, "window_seconds": 2},
    )
    assert real.json()["persisted"] is True
    history = client.get("/api/history?limit=3").json()
    assert len(history) == 1
    assert history[0]["source"] == "local"


def test_baseline_and_monitor_endpoints_are_available() -> None:
    baseline = client.get("/api/baseline?days=1").json()
    assert baseline["sample_count"] == 0
    assert baseline["used"] is False
    status = client.get("/api/monitor/status").json()
    assert status["running"] is False


def test_profile_is_returned_in_the_analysis() -> None:
    response = client.post(
        "/api/analyze",
        json={"source": "scenario", "scenario": "legit_deploy", "profile": "development"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["profile"] == "development"
    assert any("Desarrollo" in note for note in body["context_notes"])
    assert body["history_baseline"] is None  # demos never borrow real history
