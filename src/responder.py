"""Autonomous response engine (SOAR-style playbooks).

Maps a :class:`~src.detector.Detection` to a graduated response:

* score 45-64  -> ``MONITOR``    raise watch level, keep collecting evidence
* score 65-84  -> ``THROTTLE``   rate-limit the source (simulated)
* score 85+    -> ``BLOCK_IP``   block the source (simulated firewall action)
* ddos cluster -> ``BLOCK_IP``   block all participating IPs + ``ISOLATE_HOST``
                                 if the target is saturated

Every action is recorded as an :class:`Action` with a plain-language
explanation built from the detection's reasons. Actions are simulated -
SentinelAI never touches a real firewall in this project.
"""

from __future__ import annotations

import dataclasses

from .detector import Detection


@dataclasses.dataclass
class Action:
    ts: float
    action: str          # MONITOR | THROTTLE | BLOCK_IP | ISOLATE_HOST
    target: str
    attack_type: str
    score: float
    explanation: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


class ResponseEngine:
    def __init__(self):
        self.blocked: set[str] = set()
        self.throttled: set[str] = set()
        self._acted_at: dict[str, float] = {}

    def respond(self, det: Detection) -> Action | None:
        # avoid spamming the same action for the same target every second
        key = f"{det.src_ip}:{det.attack_type}"
        if det.ts - self._acted_at.get(key, -1e9) < 20:
            return None
        if det.score >= 85 or det.attack_type == "ddos":
            action = "BLOCK_IP"
            if "->" in det.src_ip:  # ddos cluster pseudo-target
                action = "BLOCK_IP"
            self.blocked.add(det.src_ip)
        elif det.score >= 65:
            action = "THROTTLE"
            self.throttled.add(det.src_ip)
        else:
            action = "MONITOR"
        self._acted_at[key] = det.ts
        explanation = (f"{action} on {det.src_ip}: risk score {det.score:.0f} "
                       f"({det.attack_type}). Evidence: " + "; ".join(det.reasons))
        return Action(ts=det.ts, action=action, target=det.src_ip,
                      attack_type=det.attack_type, score=det.score,
                      explanation=explanation)

    def block_many(self, ips, ts: float, attack_type: str, explanation: str):
        """Block a set of IPs at once (DDoS playbook) and record one action."""
        for ip in ips:
            self.blocked.add(ip)
        return Action(ts=ts, action="BLOCK_IP", target=f"{len(ips)} IPs (DDoS cluster)",
                      attack_type=attack_type, score=95.0, explanation=explanation)

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked
