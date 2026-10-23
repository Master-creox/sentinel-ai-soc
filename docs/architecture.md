# SentinelAI - Architecture

```
            ┌──────────────────────┐
            │  Traffic Simulator   │  normal users + attack campaigns
            │  (src/simulator.py)  │  brute force · port scan · DDoS
            └──────────┬───────────┘  credential stuffing · beaconing
                       │ events
                       ▼
            ┌──────────────────────┐
            │   Detection Engine   │  per-IP sliding 60s windows,
            │   (src/detector.py)  │  behavioural features, signature
            │                      │  scoring 0-100, learned baseline
            └──────────┬───────────┘
                       │ detections (score + reasons)
                       ▼
            ┌──────────────────────┐
            │  Autonomous Response │  MONITOR -> THROTTLE -> BLOCK_IP
            │  (src/responder.py)  │  DDoS cluster playbook, every
            │                      │  action explained in plain language
            └──────────┬───────────┘
                       │ state
              ┌────────┴─────────┐
              ▼                  ▼
     ┌──────────────┐   ┌───────────────┐
     │ HUD Dashboard │   │ Reports / CLI │
     │ (web_dashboard)│  │ report.py     │
     └──────────────┘   └───────────────┘
```

## Design decisions

1. **Explainable first.** The detection engine is behavioural + signature
   based and returns human-readable reasons for every score. An optional
   Isolation Forest layer (`src/ml_detector.py`) is advisory only - a SOC
   analyst must always be able to ask "why was this blocked?".
2. **Zero dependencies.** The core runs on the Python standard library,
   so anyone can clone and run the demo/dashboard instantly.
3. **Honest evaluation.** The simulator labels its own traffic; the
   engine never sees labels. `python main.py eval` reports IP-level
   precision/recall against that ground truth (100% / 100% on the
   seed-42, 600-second benchmark - synthetic data, so treat it as a
   smoke benchmark, not a production claim).
4. **Simulated response.** Blocking/throttling affects only the
   simulated traffic stream. No real firewall is touched.
