---
name: lab-experiment
description: ThreatFusion private evaluation protocol. Use before running any measurement, soak, fault, replay, RITA comparison or ML evaluation in this repo — declare before outcomes, freeze the candidate, preserve every failure and amend into a new root.
---

# Private lab experiment protocol

Follow these steps for every measured result. Never shortcut them to make a gate pass.

1. **Choose the gate.** Name the `docs/PRODUCT_PLAN.md` gate (P1–P5) the experiment serves.
2. **Root.** Create a new 0700 directory under `/home/yahya/Work/threatfusion-lab/<protocol>-vN`.
   Never inside the Git checkout. Never reuse a root that already has receipts.
3. **Declare before outcomes.** Write `plan.json` (`open('x')`, mode 0600) and its SHA-256 in
   `plan.sha256`. It must include: protocol id, `git rev-parse HEAD`, runtime/method fingerprints
   (SHA-256 of `src/threatfusion/*.py` and the method script), workload, acceptance limits and scope.
   Look at existing methods: `scripts/lab/operational_faults.py`, `scripts/lab/wallclock_soak.py`,
   `scripts/lab/measure_multiday.py`.
4. **Inputs.** Synthetic reserved addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
   2001:db8::/32) and `.test` names, or permitted local copies. Never contact suspicious
   destinations. Never print secrets, CTI cache contents or real telemetry.
5. **Run.** The method refuses a changed plan/candidate and never overwrites receipts.
   Stop only processes the experiment itself started (by PID); never touch other containers,
   VMs (Kali, `qemu:///system`) or user sessions.
6. **Failures.** Keep the first failure. A method fix or product repair is an **amendment**
   in a new root that records the earlier plan/summary hashes and the reason. Do not loosen
   acceptance after seeing outcomes; a new diagnostic must be labeled as added afterwards.
7. **Method smoke.** A short `method_smoke: true` run may validate the method; it is never
   reported as evidence.
8. **Frozen evidence.** Never inspect/tune on reserved or holdout inputs, never change ML
   identities or thresholds, never call fresh-disjoint results strict temporal, never promote
   the augmented model, never present accelerated replay as a wall-clock soak.
9. **Report.** Write measurements, every amendment and limitations to the feature doc, then
   update `PRODUCT_PLAN.md`, `PROJECT_CONTEXT.md`, the newest `RELEASE_HANDOFF.md` section and
   `CHANGELOG.md`. Results belong to the exact commit measured; later HEADs need new evidence.
