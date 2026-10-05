"""Repeat the .test DNS fixture at fixed wall-clock periods in the lab guest."""

from __future__ import annotations

import argparse
import importlib.util
import json
import time


def plan(seconds):
    return {
        "protocol": "collector-rotation-live-v1",
        "duration_seconds": seconds,
        "rotation_seconds": 30,
        "period_seconds": 10,
        "cycles_per_transport": seconds // 10,
        "expected_dns_requests": seconds // 10 * 24,
        "scope": "Internal guest bridge; existing .test UDP/TCP response-code fixture; no real DNS forwarding.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "client"))
    parser.add_argument("--seconds", type=int, default=1200)
    parser.add_argument("--protocol", choices=("udp", "tcp"), default="udp")
    args = parser.parse_args()
    if not 30 <= args.seconds <= 3600 or args.seconds % 10:
        parser.error("Duration must be 30–3600 seconds, divisible by ten")
    if args.action == "plan":
        print(json.dumps(plan(args.seconds), indent=2))
    else:
        spec = importlib.util.spec_from_file_location("fixture", "/dns_fixture.py")
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        started = time.monotonic()
        for cycle in range(args.seconds // 10):
            time.sleep(max(0, started + cycle * 10 - time.monotonic()))
            fixture.client(args.protocol)
        time.sleep(max(0, started + args.seconds - time.monotonic()))
