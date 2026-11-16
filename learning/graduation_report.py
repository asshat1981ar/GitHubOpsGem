#!/usr/bin/env python3
"""Warn-Week Telemetry -> Per-Rule Graduation Report (WU-11).

Reads JSONL gate events from ~/.gem/events.jsonl (or --events FILE) and computes per-rule hit counts,
false-positive overrides, and graduation readiness for the 2026-11-14 ENFORCE flip.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from typing import Any, Dict, List


def analyze_events(lines: List[str], min_hits_to_graduate: int = 1, max_fp_rate: float = 0.05) -> Dict[str, Any]:
    hits: Dict[str, int] = collections.Counter()
    fps: Dict[str, int] = collections.Counter()
    decisions: Dict[str, int] = collections.Counter()

    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        rec = json.loads(raw)
        decisions[str(rec.get("decision", "PASS"))] += 1
        for rule in rec.get("rules") or []:
            hits[str(rule)] += 1
            if rec.get("false_positive"):
                fps[str(rule)] += 1

    graduated: List[str] = []
    hold_in_warn: List[str] = []
    rule_stats: Dict[str, Dict[str, Any]] = {}

    for rule, count in sorted(hits.items()):
        fp = fps[rule]
        rate = round(fp / max(1, count), 4)
        ready = count >= min_hits_to_graduate and rate <= max_fp_rate
        rule_stats[rule] = {"hits": count, "false_positives": fp, "fp_rate": rate, "graduate_to_enforce": ready}
        (graduated if ready else hold_in_warn).append(rule)

    return {
        "total_events": sum(decisions.values()),
        "decisions": dict(decisions),
        "rules": rule_stats,
        "graduated_to_enforce": graduated,
        "hold_in_warn": hold_in_warn,
    }


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--events", default=os.path.expanduser("~/.gem/events.jsonl"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    lines: List[str] = []
    if os.path.exists(a.events):
        with open(a.events, encoding="utf-8") as fh:
            lines = fh.readlines()
    report = analyze_events(lines)
    if a.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"# Warn-Week Graduation Report ({report['total_events']} events)")
        print(f"- Graduated to ENFORCE: {', '.join(report['graduated_to_enforce']) or 'none'}")
        print(f"- Held in WARN: {', '.join(report['hold_in_warn']) or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
