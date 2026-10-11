"""Plain-language review list: what it is, what happened, what to do.

Built only from the validated snapshot rows; the technical view keeps every
detail. DNS items are grouped by name, so one computer with several addresses
does not repeat the same name.
"""
from __future__ import annotations

from datetime import datetime

import streamlit as st

from .i18n import tr

# Evidence labels from the snapshot -> one plain sentence each.
_PLAIN = {
    "Long bidirectional TCP session (at least 1 hour)":
        "One connection stayed open for at least an hour.",
    "Sustained periodic successful TCP connections":
        "The device contacted this address at very regular intervals.",
    "Sustained periodic bidirectional TCP with incomplete or reset termination":
        "The device contacted this address at very regular intervals.",
    "Exact known-domain IOC match": "This name is on a threat list.",
    "Hostname appears in a malicious URL IOC":
        "A link on this site is on a threat list (not necessarily the site itself).",
    "Response IP matches known threat infrastructure":
        "The address this name pointed to is on a threat list.",
    "Response IPv6 address falls within a known threat network":
        "The address this name pointed to is in a network on a threat list.",
    "High DNS query volume": "This name was looked up very often.",
    "Multiple response IPs observed": "It pointed to many different addresses.",
    "High response-IP churn rate": "Its addresses changed often.",
    "Multiple DNS query types observed": "Several kinds of lookups were made for it.",
    "Rapid DNS query burst": "Many lookups happened within a minute.",
    "High NXDOMAIN ratio in DNS responses": "Most lookups for it failed (the name does not exist).",
    "Hostname contains many numeric characters": "The name contains many digits.",
    "Hostname appears algorithmically random": "The name looks randomly generated.",
    "Periodic repeated query timing pattern": "It was looked up at very regular intervals.",
    "Sustained periodic DNS": "It was looked up at very regular intervals.",
    "Observed from multiple clients": "Several devices looked it up.",
}
_THREAT = {"Exact known-domain IOC match", "Response IP matches known threat infrastructure",
           "Response IPv6 address falls within a known threat network"}
ADVICE = {
    "threat": "Check this device first: find which program made this connection (for example with your "
              "system monitor or antivirus). If you do not recognize it, disconnect the device and get help.",
    "connection": "Usually normal for chat, music, notification, sync and update programs. "
                  "If you recognize the name, it is likely fine; if not, find which program uses it.",
    "dns": "If you recognize the name (a site or program you use), it is likely fine. "
           "If not, search for the name or ask someone you trust before doing anything else.",
    "attempt": "A program kept trying to reach something that did not answer, or something scanned "
               "several ports. Find which program it was if this repeats.",
}


# The only evidence label that contains the "; " separator itself.
_SEMICOLON_LABEL = ("Sustained periodic DNS; inspect expected software activity", "Sustained periodic DNS")


def _labels(evidence) -> list[str]:
    text = str(evidence or "").replace(*_SEMICOLON_LABEL)
    return [part.strip() for part in text.split(";") if part.strip()]


def _sentences(evidence: str) -> list[str]:
    labels = _labels(evidence)
    sentences = []
    for label in labels:
        text = _PLAIN.get(label, label)
        if text not in sentences:
            sentences.append(text)
    return sentences


def _clock(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%d.%m %H:%M")
    except (TypeError, ValueError):
        return None


def _span(first, last):
    start, end = _clock(first), _clock(last)
    return start if start == end or not end else f"{start} – {end}" if start else None


def build_review_items(view) -> list[dict]:
    """Items that need a look, most serious first. Pure function of the snapshot."""
    items = []
    for row in view.get("findings", ()):
        cti = row.get("CTI match") is True
        if row.get("Queue priority") != "Review" and not cti:
            continue
        if row.get("Declared expected") is True and not cti:
            continue
        names = [n for n in str(row.get("DNS names") or "").split(", ") if n]
        sentences = _sentences(row.get("Evidence"))
        if cti:
            sentences.insert(0, "This address is on a threat list.")
        items.append({
            "kind": "connection", "threat": cti,
            "title": names[0] if names else row.get("Responder"),
            "also": names[1:], "unnamed": not names,
            "where": ("address", row.get("Responder"), row.get("Responder port")),
            "devices": [row.get("Originator")],
            "when": _span(row.get("First observed"), row.get("Last observed")),
            "what": sentences, "advice": "threat" if cti else "connection",
        })
    by_name = {}
    for row in (view.get("dns") or {}).get("report", {}).get("findings", ()):
        if row.get("Queue priority") == "Observe":
            continue
        labels = set(_labels(row.get("Evidence")))
        item = by_name.setdefault(row["Target"], {
            "kind": "dns", "threat": False, "title": row["Target"], "also": [], "unnamed": False,
            "where": None, "devices": [], "when": None, "what": [], "advice": "dns",
            "_first": [], "_last": [], "sources": [],
        })
        for source in str(row.get("Known CTI sources") or "").split(", "):
            if source and source not in item["sources"]:
                item["sources"].append(source)
        item["threat"] |= bool(labels & _THREAT) or row.get("Queue priority") == "Investigate"
        item["devices"].append(row.get("Device"))
        for sentence in _sentences(row.get("Evidence")):
            if sentence not in item["what"]:
                item["what"].append(sentence)
        shared = [n for n in str(row.get("Same addresses as") or "").split(", ") if n]
        item["also"] = list(dict.fromkeys(item["also"] + shared))[:3]
        item["_first"].append(row.get("First observed"))
        item["_last"].append(row.get("Last observed"))
    for item in by_name.values():
        firsts = [v for v in item.pop("_first") if v]
        lasts = [v for v in item.pop("_last") if v]
        item["when"] = _span(min(firsts) if firsts else None, max(lasts) if lasts else None)
        if item["threat"]:
            item["advice"] = "threat"
        items.append(item)
    for row in (view.get("attempts") or {}).get("findings", ()):
        if row.get("Queue priority") != "Review":
            continue
        items.append({
            "kind": "attempt", "threat": False, "title": row.get("Responder"), "also": [], "unnamed": True,
            "where": ("attempts", row.get("Distinct ports"), row.get("Failed attempts")),
            "devices": [row.get("Originator")], "when": _span(row.get("First observed"), row.get("Last observed")),
            "what": ["Many connection attempts got no answer or were refused."], "advice": "attempt",
        })
    return sorted(items, key=lambda item: (not item["threat"], ("connection", "dns", "attempt").index(item["kind"]),
                                           str(item["title"])))


def _alias(value):
    text = str(value or "")
    if text.startswith("Host "):
        return tr("Host {number}", number=text[5:])
    if text.startswith("Device "):
        return tr("Device {number}", number=text[7:])
    return text


def render_review_list(view) -> None:
    items = build_review_items(view)
    threats = sum(item["threat"] for item in items)
    columns = st.columns(2)
    columns[0].metric(tr("Worth a look"), len(items))
    columns[1].metric(tr("On a threat list"), threats)
    if not items:
        st.success(tr("Nothing needs a look right now. Everything collected is listed under Details."))
        return
    st.caption(tr("A flag is a reason to look, not proof of a problem. Most flags are normal programs."))
    kinds = {"connection": "Connection", "dns": "Name lookup", "attempt": "Failed attempts"}
    for item in items[:200]:
        with st.container(border=True):
            badge = "🔴 " if item["threat"] else ""
            title = item["title"] if not item["unnamed"] else _alias(item["title"]) + " · " + tr("name unknown")
            st.markdown(f"{badge}**{title}**  \n{tr(kinds[item['kind']])}")
            if item["also"]:
                st.caption(tr("Also known as: {names}", names=", ".join(item["also"])))
            st.markdown(tr("**What happened:**") + " " + " ".join(tr(s) for s in item["what"]))
            st.markdown(tr("**What to do:**") + " " + tr(ADVICE[item["advice"]]))
            facts = [tr("Device: {device}", device=", ".join(_alias(d) for d in item["devices"] if d))]
            if item["when"]:
                facts.append(tr("When: {when}", when=item["when"]))
            if item.get("sources"):
                facts.append(tr("Lists: {sources}", sources=", ".join(item["sources"])))
            if item["where"] and item["where"][0] == "address":
                facts.append(tr("Address: {address}, port {port}", address=_alias(item["where"][1]), port=item["where"][2]))
            elif item["where"]:
                facts.append(tr("{ports} ports, {failed} failed attempts", ports=item["where"][1], failed=item["where"][2]))
            st.caption(" · ".join(facts))
    if len(items) > 200:
        st.caption(tr("Showing the first 200. Details lists everything."))
