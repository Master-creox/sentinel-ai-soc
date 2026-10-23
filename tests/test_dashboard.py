import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.web_dashboard import application

def _call(path):
    status = {}
    def start_response(s, h): status["s"] = s
    body = b"".join(application({"PATH_INFO": path}, start_response))
    return status["s"], body

def test_pages_and_api():
    s, body = _call("/")
    assert s.startswith("200") and b"SENTINEL" in body
    s, body = _call("/health")
    assert json.loads(body)["status"] == "ok"
    s, body = _call("/api/state")
    state = json.loads(body)
    assert "total_events" in state and "incidents" in state
    s, body = _call("/report")
    assert b"Incident Report" in body
