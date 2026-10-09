"""Reject known capture families being presented as new evaluation evidence.

Paths/encodings/hashes can change while the underlying traffic stays the same.
This registry is a source-history guard, not proof an unlisted source is fresh.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

# Exclude the current independent replay document: these are earlier experiments.
HISTORY = {
    **{f"CTU-Honeypot-Capture-{n}-1": "docs/evidence/NETWORK_EVALUATION.md" for n in (4, 5)},
    **{f"CTU-IoT-Malware-Capture-{n}-1": "docs/evidence/NETWORK_EVALUATION.md" for n in (44, 20)},
    **{f"CTU-IoT-Malware-Capture-{n}-1": "docs/evidence/TCP_TERMINATION.md" for n in (34, 21)},
    "CTU-IoT-Malware-Capture-8-1": "docs/evidence/TCP_ATTEMPT_REVIEW.md",
    "CTU-IoT-Malware-Capture-42-1": "docs/evidence/REVIEW_WORKLOAD.md",
    "CTU-Honeypot-Capture-7-1/Somfy-01": "docs/evidence/TCP_TERMINATION.md",
    "CTU-Honeypot-Capture-7-1/Somfy-02": "docs/evidence/REVIEW_WORKLOAD.md",
    "CTU-Honeypot-Capture-7-1/Somfy-03": "docs/evidence/REVIEW_WORKLOAD.md",
}
CURRENT = {
    "CTU-Normal-20", "CTU-Normal-21", "CTU-IoT-Malware-Capture-3-1",
    "CTU-IoT-Malware-Capture-8-1",
}


def identity(url):
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != "mcfp.felk.cvut.cz" or parts.username or parts.password or parts.port not in (None, 443):
        raise ValueError("Unsupported source identity origin")
    path = unquote(parts.path)
    match = re.search(r"/(CTU-(?:Normal-\d+|(?:IoT-Malware|Honeypot)-Capture-\d+-\d+))(?:/|$)", path)
    if not match:
        raise ValueError("Source has no recognized capture-family identity")
    result = match.group(1)
    if result.startswith("CTU-Honeypot-Capture-7-1"):
        variant = re.search(r"/Somfy-\d+(?:/|$)", path)
        if not variant:
            raise ValueError("Honeypot 7 requires a specific Somfy identity")
        result += variant.group(0).rstrip("/")
    return result


def audit(plan, *, allow_known=(), prior_only=False):
    known = dict(HISTORY)
    if not prior_only:
        known.update({key: "docs/evidence/INDEPENDENT_REPLAY.md" for key in CURRENT})
    allowed = set(allow_known)
    rows = [{"case": s["name"], "capture_identity": identity(s["url"])} for s in plan["sources"]]
    overlap = {r["capture_identity"] for r in rows if r["capture_identity"] in known}
    if allowed - overlap:
        raise ValueError("Unused known-source allowance")
    if overlap - allowed:
        raise ValueError("Previously inspected capture families require explicit known-replay declaration: " + ", ".join(sorted(overlap - allowed)))
    for row in rows:
        key = row["capture_identity"]
        row.update(history="known_replay" if key in known else "not_in_registry", reference=known.get(key))
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--allow-known", action="append", default=[])
    args = parser.parse_args()
    print(json.dumps(audit(json.loads(args.plan.read_text()), allow_known=args.allow_known), indent=2))
