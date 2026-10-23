"""Live traffic simulator.

Generates realistic background traffic plus scheduled attack campaigns
with distinct, learnable signatures:

* ``brute_force``          - one IP, many failed logins, single port
* ``port_scan``            - one IP, many unique ports, short bursts
* ``ddos``                 - many IPs, huge request rate, one port
* ``credential_stuffing``  - one IP, many usernames, high failure rate
* ``beaconing``            - one IP, tiny regular-interval DNS-like calls

The generator is deterministic for a given ``seed`` so demos and tests
are reproducible. Labels are ground truth for evaluation only.
"""

from __future__ import annotations

import random

from .events import Event

COUNTRIES = ["IN", "US", "DE", "NL", "SG", "BR", "GB", "JP", "FR", "CA"]
NORMAL_USERS = ["akash", "priya", "rahul", "sneha", "arjun", "meera", "vikram", "ananya"]
WEB_PORTS = [80, 443, 8080]
ATTACKER_POOL = [f"185.220.{i}.14" for i in range(20, 40)] + \
                [f"45.155.{i}.99" for i in range(10, 30)] + \
                [f"193.32.{i}.7" for i in range(40, 60)]


def _ip(rng: random.Random) -> str:
    return f"{rng.randint(11, 200)}.{rng.randint(0, 250)}.{rng.randint(0, 250)}.{rng.randint(1, 250)}"


class TrafficSimulator:
    """Step the simulation one second at a time with :meth:`tick`."""

    def __init__(self, seed: int = 42, attack_probability: float = 0.008):
        self.rng = random.Random(seed)
        self.t = 0.0
        self.attack_probability = attack_probability
        self.active_campaigns: list[dict] = []
        self.normal_ips = [_ip(self.rng) for _ in range(24)]

    # -- background traffic -------------------------------------------------
    def _normal_events(self) -> list[Event]:
        rng = self.rng
        out: list[Event] = []
        for _ in range(rng.randint(4, 10)):
            ip = rng.choice(self.normal_ips)
            action = rng.choices(["http", "login", "dns", "file_transfer"],
                                 weights=[55, 20, 15, 10])[0]
            out.append(Event(
                ts=self.t, src_ip=ip, country=rng.choice(COUNTRIES),
                action=action,
                port=rng.choice(WEB_PORTS if action != "dns" else [53]),
                success=rng.random() > 0.06,
                bytes_sent=rng.randint(300, 9000),
                user=rng.choice(NORMAL_USERS) if action == "login" else "",
            ))
        return out

    # -- attack campaigns ---------------------------------------------------
    def _maybe_start_campaign(self) -> None:
        if self.rng.random() > self.attack_probability or len(self.active_campaigns) >= 2:
            return
        kind = self.rng.choice(
            ["brute_force", "port_scan", "ddos", "credential_stuffing", "beaconing"])
        campaign = {"kind": kind, "until": self.t + self.rng.randint(15, 35)}
        if kind == "ddos":
            campaign["ips"] = self.rng.sample(ATTACKER_POOL, 8)
        else:
            campaign["ip"] = self.rng.choice(ATTACKER_POOL)
        if kind == "beaconing":
            campaign["until"] = self.t + 90
        self.active_campaigns.append(campaign)

    def _campaign_events(self, c: dict) -> list[Event]:
        rng = self.rng
        kind = c["kind"]
        out: list[Event] = []
        if kind == "brute_force":
            for _ in range(rng.randint(6, 12)):
                out.append(Event(self.t, c["ip"], "RU", "login", 22,
                                 success=rng.random() < 0.04,
                                 bytes_sent=rng.randint(200, 600),
                                 user="admin", label=kind))
        elif kind == "port_scan":
            for _ in range(rng.randint(10, 22)):
                out.append(Event(self.t, c["ip"], "CN", "http",
                                 rng.randint(1, 49151), success=False,
                                 bytes_sent=rng.randint(40, 120), label=kind))
        elif kind == "ddos":
            for ip in c["ips"]:
                for _ in range(rng.randint(8, 16)):
                    out.append(Event(self.t, ip, "KP", "http", 443,
                                     success=True, bytes_sent=rng.randint(400, 900),
                                     label=kind))
        elif kind == "credential_stuffing":
            for _ in range(rng.randint(6, 12)):
                out.append(Event(self.t, c["ip"], "NG", "login", 443,
                                 success=rng.random() < 0.10,
                                 bytes_sent=rng.randint(300, 700),
                                 user=f"user{rng.randint(1000, 9999)}", label=kind))
        elif kind == "beaconing":
            if int(self.t) % 10 == 0:
                out.append(Event(self.t, c["ip"], "IR", "dns", 53,
                                 success=True, bytes_sent=128, label=kind))
        return out

    # -- main step ------------------------------------------------------------
    def tick(self) -> list[Event]:
        """Advance one simulated second and return that second's events."""
        self._maybe_start_campaign()
        events = self._normal_events()
        still_active = []
        for c in self.active_campaigns:
            if self.t <= c["until"]:
                events.extend(self._campaign_events(c))
                still_active.append(c)
        self.active_campaigns = still_active
        events.sort(key=lambda e: e.ts)
        self.t += 1.0
        return events
