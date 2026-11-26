from __future__ import annotations

import time
from collections import Counter

_requests: Counter[str] = Counter()
_labels: Counter[str] = Counter()
_total_analyses = 0
_last_score = 0.0
_last_timestamp = 0.0


def count_request(path: str) -> None:
    _requests[path] += 1


def observe(label: str, score: float) -> None:
    global _total_analyses, _last_score, _last_timestamp
    _total_analyses += 1
    _labels[label] += 1
    _last_score = score
    _last_timestamp = time.time()


def render() -> str:
    lines = [
        "# HELP detector_requests_total Total de peticiones HTTP atendidas.",
        "# TYPE detector_requests_total counter",
    ]
    if not _requests:
        lines.append("detector_requests_total 0")
    for path, value in sorted(_requests.items()):
        safe = path.replace('"', "")
        lines.append(f'detector_requests_total{{path="{safe}"}} {value}')
    lines += [
        "# HELP detector_analyses_total Total de análisis ejecutados.",
        "# TYPE detector_analyses_total counter",
        f"detector_analyses_total {_total_analyses}",
        "# HELP detector_anomalies_total Análisis por clasificación.",
        "# TYPE detector_anomalies_total counter",
    ]
    if not _labels:
        lines.append('detector_anomalies_total{label="none"} 0')
    for label, value in sorted(_labels.items()):
        lines.append(f'detector_anomalies_total{{label="{label}"}} {value}')
    lines += [
        "# HELP detector_last_score Última puntuación de anomalía (0-1).",
        "# TYPE detector_last_score gauge",
        f"detector_last_score {_last_score:.3f}",
        "# HELP detector_last_analysis_timestamp Timestamp unix del último análisis.",
        "# TYPE detector_last_analysis_timestamp gauge",
        f"detector_last_analysis_timestamp {_last_timestamp:.0f}",
    ]
    return "\n".join(lines) + "\n"
