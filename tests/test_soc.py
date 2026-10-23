import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.soc import SOCEngine

def test_engine_detects_and_blocks_attackers():
    eng = SOCEngine(seed=42)
    for _ in range(600):
        eng.step()
    ev = eng.evaluation()
    assert ev["ip_recall"] >= 0.8
    assert len(eng.responder.blocked) >= 3
    state = eng.state()
    assert state["total_events"] > 3000
    assert all("label" not in e for e in state["recent_events"])  # UI never leaks labels
