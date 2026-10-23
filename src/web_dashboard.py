"""SentinelAI HUD dashboard - standard-library WSGI app.

A live engine thread advances the SOC one simulated second per real
second. The page is a dark "command center" HUD: stat cards, a live
traffic chart, the event stream, incidents, and the AI decision log
(every autonomous action with its explanation).

Run: ``python dashboard.py`` -> http://127.0.0.1:8000
"""

from __future__ import annotations

import html
import json
import threading
import time
from wsgiref.simple_server import make_server

from .report import build_report
from .soc import SOCEngine

_engine = SOCEngine(seed=42)
_lock = threading.Lock()
_started = False


def _loop() -> None:
    while True:
        with _lock:
            _engine.step()
        time.sleep(1.0)


def _ensure_started() -> None:
    global _started
    if not _started:
        _started = True
        threading.Thread(target=_loop, daemon=True).start()


PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelAI - Autonomous AI SOC</title>
<style>
:root{--bg:#04070d;--panel:#0a1220;--line:#123;--cy:#22d3ee;--mg:#f471b5;--gn:#34d399;--rd:#fb4d6d;--tx:#dbeafe}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1200px 600px at 70% -10%,#0b2138,var(--bg));color:var(--tx);font-family:'Segoe UI',system-ui,monospace}
header{display:flex;justify-content:space-between;align-items:center;padding:14px 22px;border-bottom:1px solid #164e63;background:rgba(4,10,18,.8);position:sticky;top:0;backdrop-filter:blur(6px)}
h1{font-size:22px;margin:0;letter-spacing:2px}h1 .ai{color:var(--cy);text-shadow:0 0 12px var(--cy)}
.sub{color:#7dd3fc;font-size:12px;letter-spacing:1px}
.live{color:var(--gn);font-weight:700;animation:bl 1.2s infinite}@keyframes bl{50%{opacity:.35}}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;padding:14px 22px}
.card{background:linear-gradient(180deg,#0a1626,#071020);border:1px solid #155e75;border-radius:10px;padding:12px 14px;box-shadow:0 0 18px rgba(34,211,238,.08)}
.card .k{font-size:11px;color:#7dd3fc;letter-spacing:1px}.card .v{font-size:28px;font-weight:700;margin-top:4px}
.main{display:grid;grid-template-columns:2fr 1fr;gap:12px;padding:0 22px 14px}
.panel{background:rgba(7,16,32,.9);border:1px solid #134e5e;border-radius:10px;padding:12px 14px;min-height:120px}
.panel h3{margin:0 0 10px;font-size:13px;letter-spacing:1.5px;color:var(--cy)}
table{width:100%;border-collapse:collapse;font-size:12px}td,th{padding:4px 6px;border-bottom:1px solid #0f2436;text-align:left}
.tag{padding:1px 7px;border-radius:20px;font-size:11px;font-weight:700}
.crit{background:#4c0519;color:#fda4af}.warn{background:#451a03;color:#fcd34d}.ok{background:#022c22;color:#6ee7b7}.info{background:#0c2436;color:#7dd3fc}
.act{border-left:3px solid var(--mg);padding:6px 8px;margin:6px 0;background:#0b1526;border-radius:4px;font-size:12px}
.chip{display:inline-block;border:1px solid var(--rd);color:#fda4af;border-radius:16px;padding:2px 9px;margin:2px;font-size:11px}
.small{color:#93c5fd;font-size:11px}
canvas{width:100%;height:150px}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}.main{grid-template-columns:1fr}}
</style></head><body>
<header><div><h1>SENTINEL<span class="ai">AI</span></h1><div class="sub">AUTONOMOUS AI SECURITY OPERATIONS CENTER</div></div>
<div><span class="live">● LIVE</span> <span class="small" id="clock"></span></div></header>
<div class="grid">
<div class="card"><div class="k">EVENTS PROCESSED</div><div class="v" id="sEvents">-</div></div>
<div class="card"><div class="k">SIMULATED TIME</div><div class="v" id="sTime">-</div></div>
<div class="card"><div class="k">OPEN INCIDENTS</div><div class="v" id="sInc" style="color:var(--rd)">-</div></div>
<div class="card"><div class="k">IPS BLOCKED BY AI</div><div class="v" id="sBlk" style="color:var(--mg)">-</div></div>
</div>
<div class="main">
<div>
<div class="panel"><h3>NETWORK TRAFFIC / SECOND</h3><canvas id="chart" width="900" height="150"></canvas></div>
<div class="panel" style="margin-top:12px"><h3>LIVE EVENT STREAM</h3><table><thead><tr><th>TIME</th><th>SOURCE</th><th>FROM</th><th>ACTION</th><th>PORT</th><th>STATUS</th></tr></thead><tbody id="feed"></tbody></table></div>
</div>
<div>
<div class="panel"><h3>⚠ INCIDENTS</h3><div id="incidents"></div></div>
<div class="panel" style="margin-top:12px"><h3>🤖 AI DECISIONS (AUTONOMOUS ACTIONS)</h3><div id="actions"></div></div>
<div class="panel" style="margin-top:12px"><h3>⛔ BLOCKED SOURCES</h3><div id="blocked"></div></div>
</div>
</div>
<div style="padding:0 22px 18px" class="small">Defensive research &amp; education project · all traffic and responses are simulated locally · <a style="color:var(--cy)" href="/report">download incident report</a></div>
<script>
const $=id=>document.getElementById(id);
function tag(r){return r>=85?'<span class="tag crit">CRITICAL</span>':r>=65?'<span class="tag warn">HIGH</span>':r>=45?'<span class="tag info">WATCH</span>':'<span class="tag ok">OK</span>'}
async function tick(){
 const s=await (await fetch('/api/state')).json();
 $('sEvents').textContent=s.total_events; $('sTime').textContent=s.time+'s';
 $('sInc').textContent=s.open_incidents; $('sBlk').textContent=s.blocked.length;
 $('clock').textContent=new Date().toLocaleTimeString();
 $('feed').innerHTML=s.recent_events.slice().reverse().map(e=>`<tr><td>${e.ts|0}s</td><td>${e.src_ip}</td><td>${e.country}</td><td>${e.action}</td><td>${e.port}</td><td>${e.success?'<span class="tag ok">ok</span>':'<span class="tag crit">fail</span>'}</td></tr>`).join('');
 $('incidents').innerHTML=s.incidents.length?s.incidents.map(i=>`<div class="act" style="border-color:var(--rd)"><b>#${i.id} ${i.attack_type}</b> · ${i.target}<br>${tag(i.peak_score)} peak risk ${i.peak_score|0} · status: <b>${i.status}</b></div>`).join(''):'<span class="small">No incidents yet - network is calm.</span>';
 $('actions').innerHTML=s.actions.length?s.actions.slice().reverse().map(a=>`<div class="act"><b>${a.action}</b> · ${a.target}<br><span class="small">${a.explanation}</span></div>`).join(''):'<span class="small">AI is monitoring…</span>';
 $('blocked').innerHTML=s.blocked.length?s.blocked.map(b=>`<span class="chip">${b}</span>`).join(''):'<span class="small">None</span>';
 const c=$('chart').getContext('2d');const W=900,H=150;c.clearRect(0,0,W,H);
 const data=s.series.slice(-60);const max=Math.max(20,...data.map(d=>d.events));
 c.strokeStyle='#164e63';c.beginPath();c.moveTo(0,H-30);c.lineTo(W,H-30);c.stroke();
 c.beginPath();data.forEach((d,i)=>{const x=i*(W/59),y=H-30-(d.events/max)*(H-45);i?c.lineTo(x,y):c.moveTo(x,y)});
 c.strokeStyle='#22d3ee';c.lineWidth=2;c.shadowColor='#22d3ee';c.shadowBlur=8;c.stroke();c.shadowBlur=0;
 c.beginPath();data.forEach((d,i)=>{if(!d.alerts)return;const x=i*(W/59),y=H-30-(d.events/max)*(H-45);c.moveTo(x,y);c.arc(x,y,3.5,0,7)});
 c.fillStyle='#fb4d6d';c.fill();
}
tick();setInterval(tick,1000);
</script></body></html>
"""


def application(environ, start_response):
    _ensure_started()
    path = environ.get("PATH_INFO", "/")
    if path == "/api/state":
        with _lock:
            body = json.dumps(_engine.state()).encode()
        start_response("200 OK", [("Content-Type", "application/json")])
        return [body]
    if path == "/api/eval":
        with _lock:
            body = json.dumps(_engine.evaluation()).encode()
        start_response("200 OK", [("Content-Type", "application/json")])
        return [body]
    if path == "/report":
        with _lock:
            body = build_report(_engine.state(), _engine.evaluation()).encode()
        start_response("200 OK", [("Content-Type", "text/markdown; charset=utf-8")])
        return [body]
    if path == "/health":
        start_response("200 OK", [("Content-Type", "application/json")])
        return [b'{"status":"ok","service":"sentinelai-hud"}']
    body = PAGE.encode()
    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
    return [body]


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    _ensure_started()
    print(f"SentinelAI HUD live at http://{host}:{port} (Ctrl+C to stop)")
    with make_server(host, port, application) as server:
        server.serve_forever()
