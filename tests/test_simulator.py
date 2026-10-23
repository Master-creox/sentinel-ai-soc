import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.simulator import TrafficSimulator

def test_deterministic_and_labelled():
    a, b = TrafficSimulator(seed=3), TrafficSimulator(seed=3)
    for _ in range(120):
        ea, eb = a.tick(), b.tick()
        assert [e.to_dict() for e in ea] == [e.to_dict() for e in eb]
    kinds = set()
    sim = TrafficSimulator(seed=42)
    for _ in range(900):
        for e in sim.tick():
            kinds.add(e.label)
    assert "normal" in kinds and len(kinds) >= 4  # several attack types appear
