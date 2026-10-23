import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.detector import Detection
from src.responder import ResponseEngine

def _det(score, kind="brute_force", ip="9.9.9.9", ts=100.0):
    return Detection(ts=ts, src_ip=ip, score=score, attack_type=kind,
                     features={}, reasons=["evidence"])

def test_graduated_response():
    r = ResponseEngine()
    assert r.respond(_det(50)).action == "MONITOR"
    assert r.respond(_det(70, ts=200.0)).action == "THROTTLE"
    assert r.respond(_det(95, ts=300.0)).action == "BLOCK_IP"
    assert r.is_blocked("9.9.9.9")

def test_block_many_for_ddos():
    r = ResponseEngine()
    act = r.block_many(["1.1.1.1", "2.2.2.2"], ts=0.0, attack_type="ddos",
                       explanation="cluster blocked")
    assert act.action == "BLOCK_IP" and r.is_blocked("1.1.1.1")
