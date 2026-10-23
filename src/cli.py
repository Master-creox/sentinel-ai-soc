"""Command-line interface: ``python main.py demo|report|eval``."""

from __future__ import annotations

import argparse
import json
import sys

from .report import build_report
from .soc import SOCEngine


def run_demo(seconds: int = 300, seed: int = 42) -> SOCEngine:
    engine = SOCEngine(seed=seed)
    print(f"SentinelAI demo - simulating {seconds}s of network traffic (seed={seed})")
    for _ in range(seconds):
        out = engine.step()
        for act in out["actions"]:
            print(f"  [t={int(act['ts']):>3}s] {act['action']:<9} {act['target']:<28} "
                  f"{act['attack_type']} (risk {act['score']:.0f})")
    return engine


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinelai",
                                     description="SentinelAI - Autonomous AI SOC")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("demo", "report", "eval"):
        p = sub.add_parser(name)
        p.add_argument("--seconds", type=int, default=300)
        p.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    engine = run_demo(seconds=args.seconds, seed=args.seed)
    state, evaluation = engine.state(), engine.evaluation()
    print(f"\nProcessed {state['total_events']} events | "
          f"{len(state['incidents'])} incidents | "
          f"{len(state['blocked'])} IPs blocked | "
          f"recall {evaluation['ip_recall']:.1%} precision {evaluation['ip_precision']:.1%}")
    if args.cmd == "report":
        print("\n" + build_report(state, evaluation))
    if args.cmd == "eval":
        print(json.dumps(evaluation, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
