# Independent connection coverage: IoT-23 v1

Protocol `iot23-connection-coverage-v1` selected four small official connection
logs before download/results inspection. Detector policy
`zeek-connection-context-v1` was frozen at source commit
`0a3e17c1f4724f2f3d75966b08125ee5e26c8c1d`. No threshold, model or classifier
changed after inspecting these results.

The provider describes real-device captures from 2018–2019, with benign and
malicious scenarios: [official IoT-23 description](https://www.stratosphereips.org/datasets-iot23).
Attribution: Garcia, S., Parmisano, A., and Erquiaga, M. J. (2020), *IoT-23*,
v1.0.0, [DOI 10.5281/zenodo.4743746](https://zenodo.org/records/4743746).
The [Zenodo metadata record](https://zenodo.org/api/records/4743746) declares
CC BY 4.0. Individual logs were downloaded from the provider's linked directory;
their hashes identify this acquisition, not verified byte identity with the
entire Zenodo archive. Dataset files and outputs remain local regardless of
distribution permission. No malware binaries were acquired/executed and no
observed addresses were visited.

## Aggregate observations

| Capture suffix (CTU) | Provider scenario | Rows | Observed start-time span | TCP rows | Confirmed sessions | Connection groups | Connection reviews |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Honeypot-4-1 | Benign | 452 | 21.86 h | 142 | 46 | 16 | 0 |
| Honeypot-5-1 | Benign | 1,374 | 5.49 h | 482 | 178 | 176 | 0 |
| IoT-Malware-44-1 | Malicious capture | 237 | 1.91 h | 27 | 2 | 10 | 1 |
| IoT-Malware-20-1 | Malicious capture | 3,209 | 23.98 h | 17 | 0 | 41 | 0 |

All 5,272 rows were accepted; invalid timestamp/IP/connection-field counts and
skipped rows were zero. Provider flow labels were stripped **before** analysis.
The two malicious captures contain 26/211 and 16/3,193 malicious/benign-labeled
rows respectively; capture intent is not a label on every row.

The one connection review was a long bidirectional session. The second malicious
capture produced no connection review and had no confirmed qualifying sessions.
Conservative SF/S1, bidirectional-byte and completeness requirements leave partial
or unsuccessful sessions uncovered. These findings expose a detection gap; they
do not establish that the long-session review identified malware or that all
other traffic was safe.

**Separate domain/IP fallback verdicts must not be confused with this queue.**
Honeypot-5-1 produced two Review verdicts there (high query volume, multi-client
observation and numeric-heavy hostname reasons), despite zero connection reviews.
All other fallback verdicts were Low. Consequently this experiment does not
support a claim of zero overall benign reviews or false positives.

Four small old-device captures are not representative enterprise traffic.
Connection groups and flow labels have different units; no malware FPR, recall,
RITA parity, temporal ML result or analyst efficacy is calculated. Native RITA,
CTI, ML and expected-activity declarations were disabled/not used. Historical
timestamps were preserved; spans do not mean newly collected live traffic.

## Reproduce privately

From the source environment, choose a new directory outside the checkout:

```bash
python -m scripts.lab.evaluate_iot23 \
  --directory /absolute/private/path/iot23-coverage-v1 --download
```

The script first writes an immutable plan/hash, explicitly downloads only the
four predeclared connection logs (maximum 2 MiB each), records acquisition
hashes/HTTP metadata, then verifies inputs and exports local summaries/reports.
It rejects changed detector/parser/report source fingerprints. After later policy
development, use this increment's recorded Git revision to reproduce v1; changed
code requires a distinct protocol/evaluation, never silently relabel v1 results.
It removes the provider's unusual space-separated label columns and projects
only standard connection fields. An offline copy of a completed acquisition may
be evaluated without `--download`. Existing summaries cannot be overwritten.
Source availability/content is external; different hashes are a different
acquisition, not an identical reproduction.

| Full capture ID | Acquired source SHA-256 |
| --- | --- |
| CTU-Honeypot-Capture-4-1 | `aebe40ea0e03b120265a5c7bc140dd9b0d3fe2fce65559e84776b7dd5360e71e` |
| CTU-Honeypot-Capture-5-1 | `f36db06e7d6ba7364e932a5b003f75835e004b320d70019e8a2f0ba8685d9262` |
| CTU-IoT-Malware-Capture-44-1 | `12cd99bcda78140dd5f31cf3d786642f150e42e0ebc3599190f35314e406f71f` |
| CTU-IoT-Malware-Capture-20-1 | `ef48ad72f65efd13d517223e61e4d877ba53a082ddb8159324b18d3f310d0711` |

## Automatic collector check

Each label-free capture was separately imported into fresh private collector
state, restarted and offered a gzip copy. Retained counts, groups and reviews
matched the frozen offline analysis for all four. Restarts added zero records;
each compressed copy was recognized as one duplicate. No source was mixed with
another sensor. Initial scan times were 0.25–0.44 seconds locally, with total
state files 0.17–1.67 MB. These are small single-run observations, not sustained
throughput, peak-memory or enterprise sizing measurements.

Synthetic regression tests additionally exercise rotation, interrupted snapshot
writing, conflict handling, finite retention, capacity loss, corrupt/oversized
gzip, symlinks/FIFOs, process locks, rejected-file fairness, SIGTERM and local/
public UI separation. They establish software contracts, not field efficacy.
See [collector operation](TELEMETRY_COLLECTOR.md).

## Next gates

1. Predeclare fresh development controls for partial/reset sessions, retries,
   idle/jitter and benign updates before expanding connection-policy coverage.
2. Reserve new untouched captures for evaluation; do not tune on these v1 results.
3. Measure operator review workload with an actual analyst and compare native
   RITA on appropriately scoped shared inputs. Time saved is still unmeasured.
4. Measure longer live rotation/resource behavior and evaluate whether closed-log
   latency warrants a distinct incremental-tail collector.

Frozen ML identities/thresholds and deferred strict-temporal runtime promotion
remain unchanged. Raw logs, models, caches and evaluation outputs stay private.
