# Review workload and same-source comparison

Protocol: `review-workload-v1`, 2026-10-05. This increment measures existing
behavior; it does not change a detector or promote a model. ThreatFusion remains
a local Zeek/CTI investigation prototype, with optional native RITA comparison.

## Declared conditions

The private acquisition plan preceded traffic-body acquisition and product
results. It pins baseline `c82f8d21b6867915abda7a016a2e2a62811e32f1`, two seeds
(`20261061`, `20261161`), twelve synthetic profiles and three official PCAPs.
Its SHA-256 is
`e0c146c41c809c35bd33cb30e0c6863621217e3365c5d97ddc0f3b5a24f0ee79`.
All 80 top-level runtime Python modules were frozen before analysis and remain
identical. Tooling/native-output hashes were sealed before ThreatFusion results.
The later published preparation helper reproduces the original plan exactly.

Synthetic packets represent two hours, rather than two hours of live capture.
Profiles cover irregular browsing, regular/jittered updates, regular/widely
jittered simulations, DNS TTL caching, two endpoints sharing a resolver,
benign outage/sparse attempt simulation and benign/simulated long streams.
Normal and simulated profiles intentionally overlap observable behavior.
Intent names exist only in the private manifest, never packet payloads or
detector inputs. New seeds vary generated traffic, but are not independent
real-world holdouts; regular schedules intentionally remain identical.

Official sources were selected by identity/index/HEAD metadata, not detector
results. Previously inspected Somfy-01 and Trojan-21 were avoided. General
provider descriptions/public label summaries may have been read; raw traffic
and product results for these selected sources were not inspected before the
plan. A tentative 8 MiB download bound increased to 64 MiB after HEAD revealed
the normal PCAP sizes, before any bodies/results; no source was substituted.

- [Somfy-02](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-7-1/Somfy-02/): provider-described normal device, 33,104,424 bytes.
- [Somfy-03](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-Honeypot-Capture-7-1/Somfy-03/): provider-described normal device, 17,182,720 bytes.
- [Trojan-42](https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-42-1/): malicious capture intent, 2,908,160 bytes; not per-flow malware truth.

Attribution: Garcia, S., Parmisano, A., & Erquiaga, M. J. (2020).
[IoT-23 (v1.0.0)](https://doi.org/10.5281/zenodo.4743746),
[provider description](https://www.stratosphereips.org/datasets-iot23) and
[license metadata](https://zenodo.org/api/records/4743746). Acquisition receipts
retain exact URLs, byte lengths, hashes, ETag and Last-Modified locally. No raw
source, domain list, packet payload or evaluation/state file is redistributed.

## Offline processing and integrity

Pinned Zeek image:
`activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5`.
Packet reading uses checksum verification, `--network none`, a read-only input,
private output, matching owner UID/GID, dropped capabilities and resource limits.
No traffic replay, malware execution/extraction or destination visits occur.

Native RITA v5.1.2 uses the previously pinned image/backend from `LOCAL_LAB.md`.
A separate `rita-review-runtime` preserves earlier configs and databases. Its
internal subnet declaration covers the synthetic client subnet and the provider
192.168.0.0/16 subnet. Scores/modifiers remain upstream defaults; update checks
and feeds are off. Comparison containers run as the lab input owner rather than
loosening 0700/0600 permissions. Fresh database names use no rebuild; existing
names are refused. RITA receives the same complete generated Zeek directory.
Its CSV row/severity units differ from ThreatFusion's queues and verdicts.

The first RITA import failed because its original container UID could not read
private logs. That attempt is preserved; the database was absent before retry,
and the already generated Zeek logs were reused unchanged. No scoring changed.

Two official PCAPs fail Zeek with incomplete final packet records. A separate
structural parser confirms truncation. Partial logs are excluded, never repaired,
silently sampled or counted as zero reviews. No replacement source was selected.

| Source | Raw PCAP SHA-256 | Outcome |
| --- | --- | --- |
| Somfy-02 | `2a32158374fce6635272ff8fc0ff39b88e1e759100a6384b9a2c8b14ad5dc7b6` | Complete offline/native/product evaluation |
| Somfy-03 | `1096e452a9749eb915503a58f23d997649563b6d36a2184367467a77239ba247` | Excluded: truncated packet |
| Trojan-42 | `7573797f17aae96e3804a3cfb22d531b74c17bbae740de1e14048f89130fba37` | Excluded: truncated packet |

## Aggregate observations

CTI, ML and expected-activity declarations are disabled throughout. Original
connection/domain/device/attempt policies and verdicts remain unchanged.

| Evaluated source | Connection records | DNS transactions | TCP Review / groups | DNS Review / observed-client groups | Attempt patterns | Native RITA CSV rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Development synthetic | 672 | 144 | 8 / 12 | 1 / 11 | 0 | 23 |
| Reserved synthetic | 671 | 144 | 8 / 12 | 1 / 11 | 0 | 23 |
| Somfy-02 | 52 | 52 | 1 / 2 | 1 / 2 | 0 | 1 |

Both synthetic windows have **5/7 normal TCP groups** and **3/5 simulated TCP
groups** in Review. Of endpoint-attributed DNS groups, normal activity has 1/6
in Review and simulations 0/4. A separate shared-resolver group has 16 DNS
transactions and no Review; it is attributed to neither underlying endpoint.
DNS caching reduces 60 regular connections to eight queries per endpoint.
The DNS coverage gate is therefore insufficient for those profiles, even when
connection timing is regular. All synthetic HTTP counts, DNS answers/codes,
TCP starts/states and single long-stream connections match their manifests.

| Profile | TCP review in both windows | Interpretation |
| --- | --- | --- |
| Irregular browser | No | This one workload stays outside timing review |
| Regular updater / regular simulation | Both yes | Timing alone does not establish intent |
| Jittered normal updater | Yes | Small jitter still creates normal review work |
| Widely jittered simulation | No | Existing timing coverage gap |
| Cached polling | Yes; DNS also reviews | A normal profile can enter both queues |
| Shared-resolver normal / simulation | Both yes | DNS-only origin remains the resolver |
| Benign outage / sparse attempt simulation | Both no | Sparse failures do not meet dense/diversity gates |
| Normal / simulated long stream | Both yes | Long bidirectional duration does not establish intent |

Native CSV severities: development Critical/High/Medium/Low = 6/5/2/10;
reserved = 6/4/3/10; Somfy-02 = one High row. These include normal activity and
DNS/connection metadata; they are not calibrated malware probabilities or a
comparable false-positive count. Synthetic headers/constant payload sizes,
two-hour coverage and prevalence influence native scoring. There is no new
successful malicious real-source comparison in this increment.

Separate connection-domain/IP fallback verdicts are 12 Low + one Review in each
synthetic window, and 27 Low in Somfy-02. Do not add those units to TCP/DNS queue
counts or call an IP fallback a DNS observation.

Offline connection findings/timelines/attempts and strict DNS snapshots/timelines
exactly match collected outputs for all three successful inputs. Across them,
all 1,735 mixed records are retained without rejection/pruning; retrospective
seven-day clocks preserve each full capture. Restart adds zero records and two
gzip copies per case count as duplicates. Somfy-02 has an observed start-time
span of 83,250.28138 seconds. This proves replay/reconciliation contracts, not
live latency, enterprise throughput or absence of gaps in sensor coverage.

## Reproduction

Use the source revision accompanying this document and the private Ubuntu lab
prerequisites in `LOCAL_LAB.md`. Keep the experiment outside the source repository.
Run Python commands with the project's environment activated.
These commands create synthetic packets locally, then separately acquire only
the three declared official PCAPs; they do not start a public service:

```bash
python -m scripts.lab.prepare_review_workload prepare --root /private/new-review-run
python -m scripts.lab.prepare_review_workload acquire --root /private/new-review-run
```

The preparation command refuses an existing root and freezes the current runtime.
This protocol is measured only on the runtime identity recorded above; future
runtime changes require a new protocol rather than reuse as untouched evidence.
Acquisition is explicit, bounded, checks source size/redirect origin and refuses
overwrites. Changed upstream contents require recording a new identity, not
claiming reproduction of the hashes in the table.

Inside the guest, prepare a **new** `rita-review-runtime` from the pinned RITA
assets as described in `LOCAL_LAB.md`. Add `192.168.0.0/16` to `internal_subnets`
and add `--user "$(id -u):$(id -g)"` to wrapper Docker arguments. Keep scores,
modifiers and empty feeds unchanged; record hashes/these two changes in private
`results/review-workload-v1/rita-contract.json` using the demonstrated `files`,
`changes`, `feeds_empty` fields. Start its backend before running the comparison.
Copy each private case folder into `~/threatfusion-lab/results/review-workload-v1/`
and copy the source runner into `~/threatfusion-lab/`.

```bash
bash rita-review-runtime/rita_lab.sh start
bash run_review_offline.sh development
bash run_review_offline.sh reserved
bash run_review_offline.sh somfy-02
# Execute separately: these source identities fail Zeek; preserve error receipts.
bash run_review_offline.sh somfy-03
bash run_review_offline.sh trojan-42
```

Copy complete outputs back to the private prepared root, verify original PCAP/
manifest bytes, then seal outputs and evaluate each case separately:

```bash
python -m scripts.lab.evaluate_review_workload freeze --root /private/new-review-run
python -m scripts.lab.evaluate_review_workload evaluate --root /private/new-review-run --case development
# Repeat evaluate with reserved, somfy-02, somfy-03 and trojan-42.
```

Evaluation refuses input/tooling/runtime changes, malformed or possibly capped
native exports, excessive file/record/time bounds, mismatched generated traffic
and offline/collector discrepancies. It never publishes reports automatically.
Restore the lab's prior stopped state after owned comparisons; preserve private
evidence and earlier databases. This experiment's receipts are local under
`threatfusion-lab/review-workload-v1`, outside Git.

## Product decision and next gate

The independent real-source gate is **partial**: only one normal device capture
completed and the selected malicious source failed. It supplies no enterprise
FPR, malware recall, RITA parity, analyst-time or ML promotion evidence.

Prioritize a predeclared analyst-task/workload increment: explain why a group
reviews, show overlapping normal activity, evaluate reversible scoped expectation
context and preserve suspicious/CTI-conflicting evidence. Any human efficacy claim
needs actual analyst participants. Obtain several new permitted intact normal/
malicious windows before proposing timing/sparse-failure changes; reserve new
untouched inputs and require normal workload reporting alongside added coverage.
Do not lower gates using these inspected results or infer endpoint identity from
shared resolver observations. DNS tunneling/general UDP remain separate scope.
