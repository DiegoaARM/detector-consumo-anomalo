from __future__ import annotations

import json

from backend.app import config
from backend.app import explain
from backend.app.detector import Detector
from backend.app.explain import build_explanation
from backend.app.features import build_features
from backend.app.rules import classify
from backend.app.scenarios import build_scenario


class _FakeResponse:
    def __init__(self, payload: str) -> None:
        self._payload = payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._payload.encode("utf-8")


def _context(scenario: str = "suspicious_spike") -> tuple[dict, object, object]:
    collection = build_scenario(scenario)
    features = build_features(collection.samples, collection.events)
    verdict = classify(features, Detector().score(features))
    return build_explanation(features, verdict, 0.9), features, verdict


def _enable_llm(monkeypatch, response: str) -> None:
    monkeypatch.setattr(config, "LLM_URL", "http://127.0.0.1:11434")
    monkeypatch.setattr(config, "LLM_MODEL", "llama3.2:3b")
    monkeypatch.setattr(config, "LLM_TIMEOUT", 30.0)
    monkeypatch.setattr(
        explain.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _FakeResponse(json.dumps({"response": response})),
    )


def test_summary_always_mentions_memory() -> None:
    explanation, features, _verdict = _context()
    assert "memoria " in explanation["summary"]
    assert f"{features.baseline_memory:.1f}%" in explanation["summary"]
    assert f"{features.current_memory:.1f}%" in explanation["summary"]


def test_llm_adds_reading_without_replacing_verified_numbers(monkeypatch) -> None:
    explanation, features, verdict = _context()
    base_summary = explanation["summary"]
    base_evidence = list(explanation["evidence_suspicious"])
    caveat = explanation["caveat"]

    reading = (
        "La subida de CPU coincide con el proceso nuevo y el destino externo, "
        "sin que haya una actividad declarada que lo justifique"
    )
    _enable_llm(
        monkeypatch,
        json.dumps(
            {
                "summary": reading,
                "verifications": [
                    "Verificar el proceso nuevo con el dueño del equipo",
                    "Confirmar la actividad declarada en la ventana",
                ],
            }
        ),
    )

    assert explain.maybe_enhance_with_llm(explanation, features, verdict) is True
    assert explanation["summary"].split(" Lectura:")[0] == base_summary.split(" Lectura:")[0]
    assert "Lectura:" in explanation["summary"]
    assert reading in explanation["summary"]
    assert "+" in explanation["summary"]
    assert explanation["verifications"] == [
        "Verificar el proceso nuevo con el dueño del equipo",
        "Confirmar la actividad declarada en la ventana",
    ]
    assert explanation["evidence_suspicious"] == base_evidence
    assert explanation["caveat"] == caveat


def test_poor_reading_keeps_deterministic_text_but_uses_llm_checks(monkeypatch) -> None:
    explanation, features, verdict = _context()
    base_summary = explanation["summary"]
    _enable_llm(
        monkeypatch,
        json.dumps(
            {
                "summary": "Indicios de uso indebido",
                "verifications": ["Revisar el proceso padre", "Confirmar la actividad declarada"],
            }
        ),
    )

    assert explain.maybe_enhance_with_llm(explanation, features, verdict) is True
    assert explanation["summary"] == base_summary
    assert explanation["verifications"] == ["Revisar el proceso padre", "Confirmar la actividad declarada"]


def test_raw_data_line_is_not_accepted_as_verification(monkeypatch) -> None:
    explanation, features, verdict = _context()
    base_summary = explanation["summary"]
    _enable_llm(
        monkeypatch,
        json.dumps(
            {
                "summary": "",
                "verifications": [
                    "CPU: 18%, red: 14%, procesos nuevos: idea64.exe, IPs nuevas: 1, eventos: []",
                    "Revisar el proceso padre del PID indicado",
                ],
            }
        ),
    )

    assert explain.maybe_enhance_with_llm(explanation, features, verdict) is False
    assert explanation["summary"] == base_summary


def test_contradictory_reading_is_rejected_for_normal_label(monkeypatch) -> None:
    explanation, features, verdict = _context("normal")
    base_summary = explanation["summary"]
    _enable_llm(
        monkeypatch,
        json.dumps(
            {
                "summary": (
                    "La subida de CPU coincide con el proceso nuevo y el destino externo, "
                    "sin una actividad declarada que lo explique"
                ),
                "verifications": ["Revisar el proceso padre", "Confirmar la actividad declarada"],
            }
        ),
    )

    assert explain.maybe_enhance_with_llm(explanation, features, verdict) is True
    assert explanation["summary"] == base_summary
    assert explanation["verifications"] == ["Revisar el proceso padre", "Confirmar la actividad declarada"]


def test_missing_llm_checks_falls_back_to_deterministic_explanation(monkeypatch) -> None:
    explanation, features, verdict = _context()
    base_summary = explanation["summary"]
    _enable_llm(
        monkeypatch,
        json.dumps({"summary": "", "verifications": ["Una sola verificación"]}),
    )

    assert explain.maybe_enhance_with_llm(explanation, features, verdict) is False
    assert explanation["summary"] == base_summary
