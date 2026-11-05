# Project summary

**English** • [Türkçe](PROJECT_SUMMARY.tr.md)

A one-page overview of ThreatFusion AI. Every number below comes from the
[evidence records](README.md#evidence); nothing here is newer than they are.

## Problem

A small network (a home, a lab, a small office) produces thousands of
connections a day. Finding the few that look like malware "calling home"
usually needs a full monitoring platform (SIEM, Security Onion, Malcolm) or
manual work through raw Zeek logs. ThreatFusion asks one narrower question:
**which device talked to which destination, and which of those conversations
deserve a closer look, and why?**

## Approach

1. **Collect.** A local collector imports completed Zeek `conn.log` and
   `dns.log` files and keeps the last 24 hours in a private SQLite database.
2. **Check.** Every destination is compared with three threat-intelligence
   (CTI) lists: SGB (Türkiye), ThreatFox and URLhaus. Every device →
   destination group is also checked with simple, explainable behavior rules:
   long sessions (≥ 1 hour), regular repetition (20+ connections over 30+
   minutes at very regular intervals) and failed-attempt patterns.
3. **Explain.** The *What to check* list shows only flagged groups, CTI matches
   first, each with its reason, the evidence and its coverage limits.

**Detection is driven by CTI matching and these rules.** Evidence is kept
separate by strength (exact CTI match > CTI context > behavior) and never
merged into one opaque score.

## Where machine learning fits

Machine learning is **experimental** and lives in its own tab. It never
changes the review list and never overrides CTI.

- *New for this computer*: destinations a device never used before that it
  keeps calling at a steady rhythm.
- A random-forest behavior model, trained locally on each computer after
  3 days of its own traffic plus shipped numeric features of public recordings.

Earlier models (a lexical domain-name classifier and a model trained on public
data only) failed their evaluations and are switched off. Their full history,
including the failures, is in [ML evaluation](evidence/ML_DATASET.md).

## Architecture in brief

Zeek logs → collector (checkpointed, deduplicated, bounded evidence window) →
aliased JSON snapshot → Streamlit web app bound to `127.0.0.1`. CTI lists are
cached locally; suspicious destinations are never visited or resolved, and no
data leaves the computer. Details: [Architecture](ARCHITECTURE.md).

Stack: Python 3.12, Streamlit, SQLite, pandas, scikit-learn. Linux only.

## Results so far

| Measured | Result |
| --- | --- |
| Synthetic normal and simulated traffic | Normal updaters and polling also enter Review: the rules are not yet selective enough |
| Four IoT-23 captures (2018–2019) | 0 reviews in two benign captures; one of two malicious captures produced one review, the other none |
| Fault matrix and 6-hour soak | 9/9 fault cases pass; soak passed 16/16 checks (collector peak 684 MiB) |
| One laptop, 24 h of normal real traffic | 59 groups for review, all benign; the defects behind this were fixed |
| Behavior model trained on each computer | 71 % of malware families on an unseen device, 56 % of unseen malware recordings, ≤ 1 false flag per day; only 27 % of 2025–2026 malware |
| Engineering | Lint, about 1,400 automated tests, a repository privacy audit, a container check and first-run installs on fresh Debian and Ubuntu run in CI |

## Limitations

- Detection of real, labeled malware has **not** been measured yet.
- A 7-day false-alarm test on real traffic is in progress.
- Behavior rules also match normal software (updaters, chat apps); every flag
  is a reason to look, not a verdict.
- Whether it is more useful than RITA, Security Onion or Malcolm has not been
  measured.
- Linux only; Zeek must run separately.

## Try it

After [installing](INSTALL_LINUX.md), run the app with synthetic data:

```bash
threatfusion-ai --mode demo
```

Demo results are not measurements.
