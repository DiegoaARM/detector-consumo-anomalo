from __future__ import annotations

import numpy as np

from .features import Features


def _clip(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return float(max(low, min(high, value)))


class Detector:
    """Hybrid scorer: transparent weighted rules + optional Isolation Forest.

    The rule part always runs and is the part that explains the classification.
    The forest only modulates the numeric score; it never decides the label.
    """

    WEIGHTS = {
        "cpu": 0.30,
        "net_out": 0.18,
        "new_process": 0.18,
        "external_ip": 0.16,
        "persistence": 0.12,
        "memory": 0.06,
    }

    def __init__(self) -> None:
        self.model_name = "reglas deterministas"
        self._forest = None
        try:
            from sklearn.ensemble import IsolationForest

            rng = np.random.default_rng(7)
            n = 500
            normal = np.zeros((n, 6), dtype=float)
            normal[:, 0] = np.abs(rng.normal(0, 0.18, n))  # cpu delta / 300
            normal[:, 1] = np.abs(rng.normal(0, 0.12, n))  # net delta / 600
            normal[:, 2] = rng.choice([0.0, 0.05, 0.1], n, p=[0.85, 0.12, 0.03])
            normal[:, 3] = rng.choice([0.0, 0.05], n, p=[0.96, 0.04])
            normal[:, 4] = rng.choice([0.0, 0.1], n, p=[0.97, 0.03])
            normal[:, 5] = np.abs(rng.normal(0, 0.08, n))
            self._forest = IsolationForest(
                n_estimators=120, contamination=0.05, random_state=7
            ).fit(normal)
            self.model_name = "reglas + IsolationForest"
        except Exception:
            # scikit-learn is optional: the explainable rules remain fully functional.
            self._forest = None

    def vector(self, f: Features) -> list[float]:
        return [
            _clip(max(f.cpu_delta_pct, 0) / 300),
            _clip(max(f.net_out_delta_pct, 0) / 600),
            _clip(len(f.new_high_cpu_processes) / 2),
            _clip(f.external_ip_delta / 2),
            _clip((len(f.new_run_keys) + max(f.scheduled_task_delta, 0) + len(f.risky_processes)) / 2),
            _clip(max(f.memory_delta_pct, 0) / 150),
        ]

    def rule_score(self, f: Features) -> float:
        v = self.vector(f)
        parts = [
            self.WEIGHTS["cpu"] * v[0],
            self.WEIGHTS["net_out"] * v[1],
            self.WEIGHTS["new_process"] * v[2],
            self.WEIGHTS["external_ip"] * v[3],
            self.WEIGHTS["persistence"] * v[4],
            self.WEIGHTS["memory"] * v[5],
        ]
        return _clip(sum(parts))

    def score(self, f: Features) -> float:
        rule = self.rule_score(f)
        if self._forest is None:
            return round(rule, 3)
        try:
            raw = -float(self._forest.score_samples([self.vector(f)])[0])
            forest = _clip((raw - 0.40) / 0.35)
        except Exception:
            forest = 0.0
        return round(_clip(0.65 * rule + 0.35 * forest), 3)
