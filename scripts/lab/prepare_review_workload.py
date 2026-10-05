"""Prepare the declared review-workload-v1 inputs privately; optional official acquisition."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen

from scripts.lab.evaluate_dns_collector import private_root, write_new
from scripts.lab.review_workload import create

REPO = Path(__file__).resolve().parents[2]


def declared_plan():
    # Method/source identities only; this contains no captured traffic or outputs.
    return json.loads(r"""{
  "protocol": "review-workload-v1",
  "baseline_commit": "c82f8d21b6867915abda7a016a2e2a62811e32f1",
  "sources": [
    {
      "name": "somfy-02",
      "provider_intent": "benign",
      "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-7-1/Somfy-02/2019-07-03-16-41-09-192.168.1.158.pcap",
      "head_bytes": 33104424
    },
    {
      "name": "somfy-03",
      "provider_intent": "benign",
      "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-7-1/Somfy-03/2019-07-04-16-41-10-192.168.1.158.pcap",
      "head_bytes": 17182720
    },
    {
      "name": "trojan-42",
      "provider_intent": "malicious_capture",
      "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-42-1/2019-01-10-14-34-38-192.168.1.197.pcap",
      "head_bytes": 2908160
    }
  ],
  "max_pcap_bytes": 67108864,
  "selection_note": "Selected by source identity/index/HEAD metadata only; tentative 8 MiB acquisition limit increased to 64 MiB after HEAD found 33.1/17.2 MB benign PCAPs, before any traffic bodies or product results. No source replacement.",
  "synthetic": {
    "development_seed": 20261061,
    "reserved_seed": 20261161,
    "represented_seconds": 7200,
    "profiles": [
      "irregular-browser",
      "regular-updater",
      "jittered-updater",
      "regular-heartbeat",
      "wide-jitter-heartbeat",
      "cached-polling",
      "shared-resolver-normal",
      "shared-resolver-simulation",
      "benign-outage",
      "sparse-attempt-simulation",
      "normal-long-stream",
      "simulated-long-stream"
    ]
  },
  "units": [
    "TCP connection groups",
    "DNS observed-client/domain groups",
    "attempt patterns",
    "separate aggregate domain/IP fallback verdicts"
  ],
  "acceptance": [
    "Labels never enter detector",
    "Same source for native RITA and ThreatFusion",
    "No detector/ML threshold change",
    "Input integrity, full offline/collector/timeline/restart reconciliation within existing limits; failures disclosed",
    "Measured normal review burden and controlled misses; no malware accuracy or analyst-time claim"
  ],
  "attribution": "Garcia, S., Parmisano, A., & Erquiaga, M. J. (2020). IoT-23 (v1.0.0). https://doi.org/10.5281/zenodo.4743746",
  "limits": [
    "Two historical Somfy benign windows and one malicious capture are not enterprise representative",
    "Provider capture intent is not per-flow or DNS malware truth",
    "Synthetic replay is not a two-hour live capture; new seed is not independent real traffic",
    "No malware binary execution/extraction or observed destination visits",
    "CTI, ML and expectations disabled; runtime promotion deferred"
  ]
}""")


def prepare(root):
    if root.exists():
        raise FileExistsError("Use a new private experiment root")
    root = private_root(root)
    plan = declared_plan()
    write_new(root / "plan.json", plan)
    write_new(
        root / "runtime-freeze.json",
        {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (REPO / "src/threatfusion").glob("*.py")
        },
    )
    for phase in ("development", "reserved"):
        create(root / phase, plan["synthetic"][phase + "_seed"])
    return root


def acquire(root):
    root = private_root(root)
    plan = json.loads((root / "plan.json").read_text())
    if plan != declared_plan():
        raise ValueError("Declared plan changed")
    for source in plan["sources"]:
        destination = root / source["name"]
        if destination.exists():
            raise FileExistsError("Acquisition never overwrites existing evidence")
        destination.mkdir(mode=0o700)
        url = source["url"]
        with urlopen(url, timeout=30) as response:
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "mcfp.felk.cvut.cz":
                raise ValueError("Official source redirected outside allowed origin")
            raw = response.read(plan["max_pcap_bytes"] + 1)
            metadata = {
                name: response.headers.get(name) for name in ("ETag", "Last-Modified")
            }
        if len(raw) > plan["max_pcap_bytes"] or len(raw) != source["head_bytes"]:
            raise ValueError(
                "Source size differs from declared acquisition; preserve plan"
            )
        path = destination / "scenario.pcap"
        with path.open("xb") as file:
            file.write(raw)
        path.chmod(0o600)
        write_new(
            destination / "acquisition.json",
            source
            | {
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "http_metadata": metadata,
            },
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "acquire"))
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == "prepare":
        prepare(args.root)
    else:
        acquire(args.root)
    print("Private experiment inputs prepared; no detector results or deployment")


if __name__ == "__main__":
    main()
