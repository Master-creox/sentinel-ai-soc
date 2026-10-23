import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.detector import DetectionEngine
from src.events import Event

def _feed(engine, events):
    out = []
    for i in range(0, len(events), 10):
        out += engine.ingest(events[i:i + 10])
    return out

def test_brute_force_detected_with_reasons():
    eng = DetectionEngine()
    evs = [Event(ts=float(i), src_ip="9.9.9.9", country="RU", action="login",
                 port=22, success=False, bytes_sent=300, user="admin",
                 label="brute_force") for i in range(30)]
    dets = _feed(eng, evs)
    assert dets and dets[0].attack_type == "brute_force" and dets[0].reasons

def test_port_scan_detected():
    eng = DetectionEngine()
    evs = [Event(ts=float(i % 50), src_ip="8.8.8.8", country="CN", action="http",
                 port=p, success=False, bytes_sent=80, label="port_scan")
           for i, p in enumerate(range(20, 60))]
    dets = _feed(eng, evs)
    assert any(d.attack_type == "port_scan" for d in dets)

def test_quiet_user_not_flagged():
    eng = DetectionEngine()
    evs = [Event(ts=float(i * 10), src_ip="1.2.3.4", country="IN", action="http",
                 port=443, success=True, bytes_sent=1200) for i in range(12)]
    assert _feed(eng, evs) == []
