"""Presentation-only task guidance over canonical report rows.

No lookups, identity inference, rule creation, persistence or verdict changes.
Call before translating display rows; report keys/statuses remain canonical.
"""
from __future__ import annotations



def connection_steps(row):
    if row.get("CTI match") is True:
        return (
            "Check the matched indicator source and freshness in CTI evidence; a match alone does not confirm compromise.",
            "Confirm endpoint ownership and inspect local process, proxy or endpoint logs for the same time window. Expected declarations cannot clear this CTI match.",
        )
    if row.get("Declared expected") is True:
        return (
            "Verify the declared service using inventory or endpoint logs. An unrelated process using the same endpoints can also match this declaration.",
            "Recheck expiry and traffic bounds when activity changes. Keep the original evidence; do not treat this declaration as a malware clearance.",
        )
    reason = row.get("Context reason")
    if reason == "incomplete_evidence":
        step = "Check missing fields, TCP completion and capture coverage. Incomplete evidence cannot qualify as expected activity."
    elif reason == "outside_declared_limits":
        step = "Compare the full observed window with declaration dates, counts, durations and bytes. Investigate the difference before changing any limits."
    else:
        step = "Check endpoint ownership, exact IP/port/protocol and declaration expiry. Add bounded context only after independently verifying the service; periodicity alone cannot identify it."
    return (step, "Inspect timing, bytes and termination states alongside endpoint or proxy evidence. Connection metadata does not identify a URL, downloaded file or executed process.")


