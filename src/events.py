"""Network event model used across SentinelAI.

An :class:`Event` is one observed network/auth action. The simulator
generates labelled events (``label`` is ground truth used only for
evaluation - the detector never sees it).
"""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class Event:
    ts: float                 # simulated epoch seconds
    src_ip: str
    country: str
    action: str               # "http", "login", "dns", "file_transfer"
    port: int
    success: bool = True      # login/connection success
    bytes_sent: int = 0
    user: str = ""
    label: str = "normal"     # ground truth: normal|brute_force|port_scan|ddos|credential_stuffing|beaconing

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)
