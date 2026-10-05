"""Presentation-only task guidance over canonical report rows.

No lookups, identity inference, rule creation, persistence or verdict changes.
Call before translating display rows; report keys/statuses remain canonical.
"""
from __future__ import annotations

import streamlit as st

from .i18n import tr


def review_counts(rows):
    """Count retained TCP groups before view filters; CTI overrides context."""
    return {
        "Original TCP reviews": sum(r.get("Queue priority") == "Review" for r in rows),
        "Declared expected reviews": sum(
            r.get("Queue priority") == "Review" and r.get("Declared expected") is True
            and r.get("CTI match") is not True for r in rows
        ),
        "Unexplained / CTI groups": sum(
            (r.get("Queue priority") == "Review" and r.get("Declared expected") is not True)
            or r.get("CTI match") is True for r in rows
        ),
        "TCP CTI groups": sum(r.get("CTI match") is True for r in rows),
    }


def render_review_summary(rows):
    columns = st.columns(4)
    for column, (label, count) in zip(columns, review_counts(rows).items(), strict=True):
        column.metric(tr(label), count)
    st.caption(tr(
        "Before filters: {count} retained TCP groups. CTI groups are included in the unexplained queue even without a behavior Review; counts overlap. DNS and attempt queues are separate.",
        count=len(rows),
    ))
    st.caption(tr(
        "Declarations change review context, not original priority. Reveal expected activity with the checkbox; exports retain all groups."
    ))


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


def render_connection_guidance(row):
    if "Queue priority" not in row:
        return  # Legacy/minimal snapshots cannot support a task explanation.
    st.markdown(f"**{tr('Review guidance')}**")
    st.caption(tr("Original queue priority: {priority}", priority=tr(str(row["Queue priority"]))))
    evidence = str(row.get("Evidence", ""))
    if evidence:
        st.write(tr("Observed evidence: {evidence}", evidence="; ".join(tr(v) for v in evidence.split("; "))))
    else:
        st.caption(tr("No TCP behavior review gate crossed. Check CTI and coverage separately."))
    if row.get("CTI match") is True:
        st.warning(tr("Destination CTI evidence takes precedence over expected activity. Review this group."))
    elif row.get("Declared expected") is True:
        st.info(tr("Declared expected activity; software identity is unverified and the original finding is retained."))
    limits = row.get("Coverage limits")
    if limits:
        st.caption(tr("Evidence limits: {limits}", limits="; ".join(tr(v) for v in str(limits).split("; "))))
    for step in connection_steps(row):
        st.write(tr(step))


def render_dns_guidance(row):
    st.markdown(f"**{tr('Review guidance')}**")
    st.caption(tr("Original queue priority: {priority}", priority=tr(str(row["Queue priority"]))))
    st.write(tr("Confirm whether the observed address is an endpoint, shared resolver or NAT using network inventory and resolver logs. Do not attribute a shared resolver's queries to individual machines."))
    if row.get("Known CTI sources"):
        st.write(tr("Check the indicator source and freshness in CTI evidence, then correlate the query time with local connection or endpoint logs."))
    else:
        st.write(tr("Check distinct query times, observed span and response codes. Updates and retries can resemble periodic activity; cached DNS can hide repeated connections."))
    if row.get("Coverage limits"):
        st.caption(tr("Evidence limits: {limits}", limits="; ".join(tr(v) for v in str(row["Coverage limits"]).split("; "))))
    st.caption(tr("A DNS query does not prove a connection, download or execution. Device and connection aliases cannot be joined by their numbers."))
