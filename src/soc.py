"""SentinelAI orchestrator: simulator -> detector -> responder.

Runs the whole SOC loop and keeps the state the dashboard and reports
need: recent events, detections, autonomous actions, incidents and
evaluation counters (against simulator ground truth, for the built-in
benchmark only).
"""

from __future__ import annotations

import dataclasses
from collections import deque

from .detector import DetectionEngine, ddos_cluster
from .events import Event
from .responder import ResponseEngine
from .simulator import TrafficSimulator


@dataclasses.dataclass
class Incident:
    id: int
    started: float
    attack_type: str
    target: str
    peak_score: float
    status: str = "open"        # open | contained

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


class SOCEngine:
    def __init__(self, seed: int = 42):
        self.simulator = TrafficSimulator(seed=seed)
        self.detector = DetectionEngine()
        self.responder = ResponseEngine()
        self.time = 0.0
        self.total_events = 0
        self.recent_events: deque[dict] = deque(maxlen=60)
        self.detections: deque[dict] = deque(maxlen=100)
        self.actions: deque[dict] = deque(maxlen=100)
        self.incidents: dict[str, Incident] = {}
        self._incident_seq = 0
        self.series: deque[dict] = deque(maxlen=120)   # per-second counters for charts
        # evaluation vs ground truth (benchmark only)
        self.eval_counts = {"attack_events": 0, "detected_attack_ips": set(),
                            "flagged_ips": set(), "attack_ips": set()}

    # -- one simulated second ---------------------------------------------------
    def step(self) -> dict:
        raw_events = self.simulator.tick()
        self.time = self.simulator.t
        # blocked sources are cut off at the (simulated) firewall
        events = [e for e in raw_events if not self.responder.is_blocked(e.src_ip)]
        dropped = len(raw_events) - len(events)
        self.total_events += len(events)

        detections = self.detector.ingest(events)
        cluster = ddos_cluster(detections, events)
        cluster_ips: set[str] = set()
        if cluster:
            detections.append(cluster)
            port = cluster.features.get("port")
            per_ip: dict[str, int] = {}
            for e in events:
                if e.port == port:
                    per_ip[e.src_ip] = per_ip.get(e.src_ip, 0) + 1
            cluster_ips = {ip for ip, c in per_ip.items() if c >= 5}

        new_actions = []
        for det in detections:
            self.detections.append(det.to_dict())
            self._open_incident(det)
            if det.attack_type == "ddos" and cluster_ips:
                act = self.responder.block_many(
                    sorted(cluster_ips), det.ts, "ddos",
                    f"BLOCK_IP on {len(cluster_ips)} IPs (DDoS cluster): risk score 95 "
                    f"(ddos). Evidence: " + "; ".join(det.reasons))
                new_actions.append(act.to_dict())
                self.actions.append(act.to_dict())
                if self.incidents:
                    self.incidents[f"{det.src_ip}:ddos"].status = "contained"
                continue
            act = self.responder.respond(det)
            if act:
                new_actions.append(act.to_dict())
                self.actions.append(act.to_dict())
                self._contain_incident(act)

        for e in events:
            if e.label != "normal":
                self.eval_counts["attack_events"] += 1
                self.eval_counts["attack_ips"].add(e.src_ip)
        for d in detections:
            if "->" not in d.src_ip:
                self.eval_counts["flagged_ips"].add(d.src_ip)
        self.eval_counts["flagged_ips"] |= cluster_ips
        self.eval_counts["detected_attack_ips"] = \
            self.eval_counts["flagged_ips"] & self.eval_counts["attack_ips"]

        second = {"t": int(self.time), "events": len(events), "dropped": dropped,
                  "alerts": len(detections)}
        self.series.append(second)
        for e in events[-14:]:
            self.recent_events.append(self._event_view(e))
        return {"second": second, "detections": [d.to_dict() for d in detections],
                "actions": new_actions}

    # -- incidents ----------------------------------------------------------------
    def _open_incident(self, det) -> None:
        key = f"{det.src_ip}:{det.attack_type}"
        if key not in self.incidents:
            self._incident_seq += 1
            self.incidents[key] = Incident(id=self._incident_seq, started=det.ts,
                                           attack_type=det.attack_type,
                                           target=det.src_ip, peak_score=det.score)
        else:
            self.incidents[key].peak_score = max(self.incidents[key].peak_score, det.score)

    def _contain_incident(self, act) -> None:
        key = f"{act.target}:{act.attack_type}"
        if key in self.incidents and act.action in ("BLOCK_IP", "THROTTLE"):
            self.incidents[key].status = "contained"

    # -- views ----------------------------------------------------------------------
    @staticmethod
    def _event_view(e: Event) -> dict:
        d = e.to_dict()
        d.pop("label", None)     # the SOC UI never shows ground-truth labels
        return d

    def state(self) -> dict:
        return {
            "time": int(self.time),
            "total_events": self.total_events,
            "blocked": sorted(self.responder.blocked),
            "throttled": sorted(self.responder.throttled),
            "open_incidents": sum(1 for i in self.incidents.values() if i.status == "open"),
            "incidents": [i.to_dict() for i in
                          sorted(self.incidents.values(), key=lambda x: -x.started)[:12]],
            "recent_events": list(self.recent_events)[-25:],
            "detections": list(self.detections)[-20:],
            "actions": list(self.actions)[-20:],
            "series": list(self.series),
        }

    def evaluation(self) -> dict:
        attack_ips = self.eval_counts["attack_ips"]
        detected = self.eval_counts["detected_attack_ips"]
        flagged = self.eval_counts["flagged_ips"]
        recall = len(detected) / len(attack_ips) if attack_ips else 0.0
        precision = (len(detected) / len(flagged)) if flagged else 0.0
        return {"attacking_ips": len(attack_ips), "detected_attacking_ips": len(detected),
                "flagged_ips": len(flagged), "ip_recall": round(recall, 3),
                "ip_precision": round(precision, 3),
                "note": "IP-level detection vs simulator ground truth; "
                        "the detector itself is purely behavioural."}
