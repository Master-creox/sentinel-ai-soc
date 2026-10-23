"""Detection engine.

For every source IP, SentinelAI maintains a sliding 60-second window of
behavioural features (request rate, failed logins, unique ports, distinct
usernames, failure ratio, small-packet regularity). Each second, IPs are
scored 0-100 and matched against attack signatures.

The scoring is deliberately *explainable*: every detection returns the
feature values and the signature rules that fired, so the autonomous
responder (and a human analyst) can see exactly why an IP was flagged.
No labels are used - detection is purely behavioural.
"""

from __future__ import annotations

import dataclasses
import statistics
from collections import defaultdict, deque

from .events import Event

WINDOW = 60.0


@dataclasses.dataclass
class Detection:
    ts: float
    src_ip: str
    score: float
    attack_type: str           # best-matching signature or "anomalous"
    features: dict
    reasons: list[str]

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _features(events: list[Event]) -> dict:
    n = len(events)
    failed_logins = sum(1 for e in events if e.action == "login" and not e.success)
    logins = sum(1 for e in events if e.action == "login")
    return {
        "events": n,
        "rate_per_min": n * (60.0 / WINDOW),
        "failed_logins": failed_logins,
        "failure_ratio": (failed_logins / logins) if logins else 0.0,
        "unique_ports": len({e.port for e in events}),
        "unique_users": len({e.user for e in events if e.user}),
        "small_packets": sum(1 for e in events if e.bytes_sent <= 160),
    }


class DetectionEngine:
    def __init__(self, alert_threshold: float = 45.0):
        self.alert_threshold = alert_threshold
        self._windows: dict[str, deque[Event]] = defaultdict(deque)
        # baseline of normal per-IP rates, learned online (median window size)
        self._baseline_rates: list[float] = []

    def ingest(self, events: list[Event]) -> list[Detection]:
        now = events[-1].ts if events else 0.0
        touched: set[str] = set()
        for e in events:
            self._windows[e.src_ip].append(e)
            touched.add(e.src_ip)
        detections: list[Detection] = []
        for ip in touched:
            w = self._windows[ip]
            while w and now - w[0].ts > WINDOW:
                w.popleft()
            if len(w) >= 4:
                det = self._score(ip, list(w), now)
                if det and det.score >= self.alert_threshold:
                    detections.append(det)
        # learn baseline from quiet IPs
        quiet = [len(w) for ip, w in self._windows.items() if len(w) <= 6]
        if quiet:
            self._baseline_rates.append(statistics.median(quiet))
            self._baseline_rates = self._baseline_rates[-300:]
        return detections

    # -- scoring -------------------------------------------------------------
    def _score(self, ip: str, events: list[Event], now: float) -> Detection | None:
        f = _features(events)
        baseline = statistics.median(self._baseline_rates) if self._baseline_rates else 3.0
        score = 0.0
        reasons: list[str] = []
        candidates: list[tuple[float, str]] = []

        # generic rate anomaly (z-score-like vs learned baseline)
        if f["events"] > max(12, baseline * 5):
            s = min(35.0, (f["events"] / max(baseline, 1.0)) * 4)
            score += s
            candidates.append((s, "anomalous"))
            reasons.append(f"request rate {f['events']} events/min-window is "
                           f"{f['events'] / max(baseline, 1.0):.1f}x the learned baseline")

        # brute force signature
        if f["failed_logins"] >= 8 and f["unique_ports"] <= 3 and f["unique_users"] <= 2:
            s = min(60.0, 25 + f["failed_logins"] * 1.5)
            score += s
            candidates.append((s, "brute_force"))
            reasons.append(f"{f['failed_logins']} failed logins on few ports/users "
                           f"(failure ratio {f['failure_ratio']:.0%})")

        # credential stuffing signature
        if f["failed_logins"] >= 8 and f["unique_users"] >= 6:
            s = min(60.0, 25 + f["unique_users"] * 1.5)
            score += s
            candidates.append((s, "credential_stuffing"))
            reasons.append(f"{f['failed_logins']} failed logins across "
                           f"{f['unique_users']} different usernames")

        # port scan signature
        if f["unique_ports"] >= 12:
            s = min(60.0, 20 + f["unique_ports"] * 1.2)
            score += s
            candidates.append((s, "port_scan"))
            reasons.append(f"{f['unique_ports']} unique destination ports in 60s")

        # beaconing signature: repeated identical tiny packets
        if f["small_packets"] >= 5 and f["events"] <= f["small_packets"] + 3:
            s = 50.0
            score += s
            candidates.append((s, "beaconing"))
            reasons.append(f"{f['small_packets']} identical tiny packets at regular intervals")

        if score <= 0:
            return None
        attack_type = max(candidates)[1] if candidates else "anomalous"
        return Detection(ts=now, src_ip=ip, score=round(min(score, 100.0), 1),
                         attack_type=attack_type, features=f, reasons=reasons)


def ddos_cluster(detections: list[Detection], events: list[Event]) -> Detection | None:
    """Detect a distributed flood: many IPs hammering one port at once."""
    if not events:
        return None
    by_port: dict[int, set[str]] = defaultdict(set)
    counts: dict[int, int] = defaultdict(int)
    for e in events:
        by_port[e.port].add(e.src_ip)
        counts[e.port] += 1
    for port, ips in by_port.items():
        if len(ips) >= 6 and counts[port] >= 60:
            return Detection(
                ts=events[-1].ts, src_ip=f"{len(ips)} IPs -> port {port}",
                score=95.0, attack_type="ddos",
                features={"events": counts[port], "unique_ips": len(ips), "port": port},
                reasons=[f"{counts[port]} requests from {len(ips)} different IPs "
                         f"hit port {port} in a single second"])
    return None
