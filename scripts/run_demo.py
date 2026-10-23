#!/usr/bin/env python3
"""Convenience wrapper: python scripts/run_demo.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.cli import main
if __name__ == "__main__":
    raise SystemExit(main(["demo", "--seconds", "300"]))
