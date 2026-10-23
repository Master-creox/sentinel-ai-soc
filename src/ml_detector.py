"""Optional ML layer: Isolation Forest over per-IP behaviour windows.

Requires scikit-learn (``pip install -r requirements-ml.txt``). It is an
*experiment* that complements the explainable engine in
:mod:`src.detector`: it learns "normal" per-IP behaviour from the
simulator's quiet traffic and flags statistical outliers. The explainable
engine remains the source of autonomous actions - ML scores are advisory,
because a SOC analyst must always be able to ask "why?".
"""

from __future__ import annotations

from .detector import _features
from .events import Event


class MLAnomalyDetector:
    def __init__(self, contamination: float = 0.05):
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "scikit-learn is not installed - run: pip install -r requirements-ml.txt"
            ) from exc
        self._model = IsolationForest(n_estimators=200, contamination=contamination,
                                      random_state=42)
        self._fitted = False

    @staticmethod
    def _vector(events: list[Event]) -> list[float]:
        f = _features(events)
        return [f["events"], f["failed_logins"], f["failure_ratio"] * 100,
                f["unique_ports"], f["unique_users"], f["small_packets"]]

    def fit(self, windows: list[list[Event]]) -> None:
        self._model.fit([self._vector(w) for w in windows])
        self._fitted = True

    def is_anomalous(self, events: list[Event]) -> bool:
        if not self._fitted:
            raise RuntimeError("call fit() first")
        return bool(self._model.predict([self._vector(events)])[0] == -1)
