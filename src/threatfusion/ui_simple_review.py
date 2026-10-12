"""Alarm list: one compact row per item (what, device -> destination, when).

Modelled on consumer network monitors (one line per alarm, open for details,
look up the destination, mute what you recognize) and on RITA's beacon list
(source, destination, connection count). Built only from the validated
snapshot; the technical view keeps every detail. DNS items are grouped by
name, so one computer with several addresses does not repeat the same name.
"""
from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import streamlit as st

from .i18n import tr

# Evidence label from the snapshot -> (short label, one plain sentence).
_REASONS = {
    "Exact known-domain IOC match": ("On a threat list", "This name is on a threat list."),
    "Response IP matches known threat infrastructure":
        ("Address on a threat list", "The address this name pointed to is on a threat list."),
    "Response IPv6 address falls within a known threat network":
        ("Address on a threat list", "The address this name pointed to is in a network on a threat list."),
    "Hostname appears in a malicious URL IOC":
        ("Listed link on this site", "A link on this site is on a threat list (not necessarily the site itself)."),
    "Long bidirectional TCP session (at least 1 hour)":
        ("Long connection", "One connection stayed open for at least an hour."),
    "Sustained periodic successful TCP connections":
        ("Regular repeats", "The device contacted this address at very regular intervals."),
    "Sustained periodic bidirectional TCP with incomplete or reset termination":
        ("Regular repeats", "The device contacted this address at very regular intervals."),
    "Periodic repeated query timing pattern": ("Regular lookups", "It was looked up at very regular intervals."),
    "Sustained periodic DNS": ("Regular lookups", "It was looked up at very regular intervals."),
    "Hostname appears algorithmically random": ("Random-looking name", "The name looks randomly generated."),
    "High NXDOMAIN ratio in DNS responses":
        ("Failed lookups", "Most lookups for it failed (the name does not exist)."),
    "High DNS query volume": ("Frequent lookups", "This name was looked up very often."),
    "Rapid DNS query burst": ("Frequent lookups", "Many lookups happened within a minute."),
    "Multiple response IPs observed": (None, "It pointed to many different addresses."),
    "High response-IP churn rate": (None, "Its addresses changed often."),
    "Multiple DNS query types observed": (None, "Several kinds of lookups were made for it."),
    "Hostname contains many numeric characters": (None, "The name contains many digits."),
    "Observed from multiple clients": (None, "Several devices looked it up."),
}
_THREAT = {"Exact known-domain IOC match", "Response IP matches known threat infrastructure",
           "Response IPv6 address falls within a known threat network"}
ADVICE = {
    "threat": "Check this device: which program made this? If you do not know it, disconnect it from the internet.",
    "connection": "Know the name? Then it is likely fine. If not, find which program uses it.",
    "dns": "Know the name? Then it is likely fine. If not, look it up before doing anything else.",
    "attempt": "If this repeats, find which program it is.",
}
# The only evidence label that contains the "; " separator itself.
_SEMICOLON_LABEL = ("Sustained periodic DNS; inspect expected software activity", "Sustained periodic DNS")


def _labels(evidence) -> list[str]:
    text = str(evidence or "").replace(*_SEMICOLON_LABEL)
    return [part.strip() for part in text.split(";") if part.strip()]


def _sentences(evidence) -> list[str]:
    sentences = []
    for label in _labels(evidence):
        text = _REASONS.get(label, (None, label))[1]
        if text not in sentences:
            sentences.append(text)
    return sentences


def _short(evidence, fallback) -> str:
    for label in _labels(evidence):
        short = _REASONS.get(label, (None, None))[0]
        if short:
            return short
    return fallback


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


def _number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


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
        label = "On a threat list" if cti else _short(row.get("Evidence"), "Unusual connection")
        duration, interval = _number(row.get("Max duration (s)")), _number(row.get("Periodic interval (s)"))
        if label == "Long connection" and duration:
            metric = ("{hours} h open", {"hours": f"{duration / 3600:.1f}"})
        elif label == "Regular repeats" and interval:
            metric = ("every {minutes} min · {count}×", {"minutes": f"{interval / 60:.0f}", "count": row.get("Connections")})
        else:
            metric = ("{count} connections", {"count": row.get("Connections")})
        items.append({
            "kind": "connection", "threat": cti, "label": label, "metric": metric,
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
            "where": None, "devices": [], "when": None, "what": [], "advice": "dns", "label": None,
            "metric": None, "_first": [], "_last": [], "_events": 0, "_evidence": [], "sources": [],
        })
        for source in str(row.get("Known CTI sources") or "").split(", "):
            if source and source not in item["sources"]:
                item["sources"].append(source)
        item["threat"] |= bool(labels & _THREAT) or row.get("Queue priority") == "Investigate"
        item["devices"].append(row.get("Device"))
        item["_evidence"].append(row.get("Evidence"))
        item["_events"] += _number(row.get("Telemetry events")) or 0
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
        item["label"] = _short("; ".join(str(e) for e in item.pop("_evidence")), "Unusual lookups")
        item["metric"] = ("{count} lookups", {"count": item.pop("_events")})
        if item["threat"]:
            item["advice"] = "threat"
        items.append(item)
    for row in (view.get("attempts") or {}).get("findings", ()):
        if row.get("Queue priority") != "Review":
            continue
        items.append({
            "kind": "attempt", "threat": False, "title": row.get("Responder"), "also": [], "unnamed": True,
            "label": "Failed attempts",
            "metric": ("{ports} ports · {failed} failed", {"ports": row.get("Distinct ports"), "failed": row.get("Failed attempts")}),
            "where": ("attempts", row.get("Distinct ports"), row.get("Failed attempts")),
            "devices": [row.get("Originator")], "when": _span(row.get("First observed"), row.get("Last observed")),
            "what": ["Many connection attempts got no answer or were refused."], "advice": "attempt",
        })
    return sorted(items, key=lambda item: (not item["threat"], ("connection", "dns", "attempt").index(item["kind"]),
                                           str(item["title"])))


def item_key(item) -> str:
    return f"{item['kind']}:{item['title']}"


def load_hidden(path: Path | None) -> set[str]:
    if path is None:
        return set()
    try:
        values = json.loads(path.read_text())
    except (OSError, ValueError):
        return set()
    return {v for v in values.get("hidden", []) if isinstance(v, str)} if isinstance(values, dict) else set()


def save_hidden(path: Path, hidden: set[str]) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".review-hidden-")
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump({"schema_version": 1, "hidden": sorted(hidden)[:5000]}, handle, indent=2)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


LABELS = ("known", "unsure", "suspicious")
MAX_LABELS = 20_000


def load_labels(path: Path | None, legacy_hidden: Path | None = None) -> dict[str, dict]:
    """Item key -> {"label", "at"}; items hidden with the older button count as known."""
    labels: dict[str, dict] = {}
    for key in load_hidden(legacy_hidden):
        labels[key] = {"label": "known", "at": None}
    if path is None:
        return labels
    try:
        values = json.loads(path.read_text()).get("labels", {})
    except (OSError, ValueError, AttributeError):
        return labels
    if isinstance(values, dict):
        for key, entry in values.items():
            if isinstance(key, str) and isinstance(entry, dict) and entry.get("label") in LABELS:
                labels[key] = {"label": entry["label"], "at": entry.get("at") if isinstance(entry.get("at"), str) else None}
    return labels


def save_label(path: Path, key: str, label: str | None, *, now: datetime | None = None) -> dict[str, dict]:
    """Set or clear (None) one label; private file, atomic replace."""
    labels = load_labels(path)
    if label is None:
        labels.pop(key, None)
    elif label in LABELS:
        labels[key] = {"label": label, "at": (now or datetime.now(timezone.utc)).isoformat()}
    kept = dict(sorted(labels.items(), key=lambda item: item[1].get("at") or "")[-MAX_LABELS:])
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".review-labels-")
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump({"schema_version": 1, "labels": kept}, handle, indent=1)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return kept


def _show(value) -> str:
    text = str(value or "")
    if text.startswith("Host "):
        return tr("Host {number}", number=text[5:])
    if text.startswith("Device "):
        return tr("Device {number}", number=text[7:])
    return text


@st.cache_resource(show_spinner=False)
def _ip_owner_reader(db_path: str):
    from .ip_owners import IPOwnerReader
    return IPOwnerReader(Path(db_path))


def ip_owner_lookup(cti_db_path: Path | None):
    if cti_db_path is None:
        return None
    reader = _ip_owner_reader(str(cti_db_path))
    if not reader:
        _ip_owner_reader.clear()  # table not downloaded yet; look again on the next render
        return None
    return reader.lookup


def _address_of(item) -> str | None:
    """The real destination IP of an item, when this screen shows one (not an alias)."""
    where = item.get("where") or ()
    candidates = [where[1]] if len(where) > 1 and where[0] == "address" else []
    for value in [*candidates, item.get("title")]:
        try:
            return str(ipaddress.ip_address(str(value)))
        except ValueError:
            continue
    return None


def lookup_links(name: str | None, address: str | None) -> list[tuple[str, str]]:
    """Outside lookup sites: VirusTotal for the name (or IP), AbuseIPDB for the IP, urlscan for both."""
    links = []
    primary = name or address
    if primary:
        links.append(("VirusTotal", "https://www.virustotal.com/gui/search/" + quote(str(primary), safe="")))
    if address:
        links.append(("AbuseIPDB", "https://www.abuseipdb.com/check/" + quote(address, safe="")))
    if name and name != address:
        links.append(("urlscan", "https://urlscan.io/domain/" + quote(str(name), safe="")))
    elif address:
        links.append(("urlscan", "https://urlscan.io/ip/" + quote(address, safe="")))
    return links


def _rerun() -> None:
    """Redraw only the auto-refreshing collector fragment when possible, else the page."""
    try:
        st.rerun(scope="fragment")
    except st.errors.StreamlitAPIException:
        st.rerun()


_BADGES = {"suspicious": "🟣 Suspicious", "unsure": "⚪ Not sure", "known": "✓ I know this"}
_BUTTONS = (("known", "✓ I know this"), ("unsure", "? Not sure"), ("suspicious", "⚠ Suspicious"))


def _render_label_buttons(item, labels, labels_path):
    key = item_key(item)
    current = (labels.get(key) or {}).get("label")
    row = st.container(horizontal=True, gap="small")
    for label, text in _BUTTONS:
        selected = current == label
        if row.button(tr(text), key=f"label-{label}-{key}", type="primary" if selected else "secondary",
                         help=tr("Click again to remove the mark") if selected else None):
            try:
                save_label(labels_path, key, None if selected else label)
            except OSError:
                st.warning(tr("Could not save. Check the folder permissions."))
            _rerun()


def _render_item(item, labels, labels_path, ip_owner=None):
    with st.container(border=True):
        icon = "🔴" if item["threat"] else "🟡"
        name = item["title"] if not item["unnamed"] else _show(item["title"])
        badge = _BADGES.get((labels.get(item_key(item)) or {}).get("label"))
        left, middle, right = st.columns([5, 4, 2])
        left.markdown(f"{icon} **{name}**" + (f" · {tr(badge)}" if badge else "")
                      + f"  \n{tr(item['label'])} · {tr(item['metric'][0], **item['metric'][1])}")
        devices = ", ".join(dict.fromkeys(_show(d) for d in item["devices"] if d))
        address = _address_of(item)
        if item["where"] and item["where"][0] == "address":
            middle.markdown(f"`{devices}` → `{_show(item['where'][1])}:{item['where'][2]}`")
        else:
            middle.markdown(f"`{devices}`")
        owner = ip_owner(address) if ip_owner and address else None
        if owner:
            middle.caption(owner.label)
        right.markdown(item["when"] or "")
        if labels_path is not None:
            _render_label_buttons(item, labels, labels_path)
        with st.expander(tr("Why? What to do?")):
            st.markdown(" ".join(tr(s) for s in item["what"]))
            st.markdown("**" + tr(ADVICE[item["advice"]]) + "**")
            facts = []
            if item["also"]:
                facts.append(tr("Same addresses as: {names}", names=", ".join(item["also"])))
            if item.get("sources"):
                facts.append(tr("Lists: {sources}", sources=", ".join(item["sources"])))
            if facts:
                st.caption(" · ".join(facts))
            target = item["title"] if not str(item["title"]).startswith(("Host ", "Device ")) else None
            links = lookup_links(target, address)
            if links:
                st.caption(tr("Look up on outside sites (opens in a new tab; the name or IP is sent to that site):"))
                for column, (label, url) in zip(st.columns(len(links)), links):
                    column.link_button(label, url)


def render_review_list(view, *, labels_path: Path | None = None, legacy_hidden_path: Path | None = None,
                       ip_owner=None) -> None:
    items = build_review_items(view)
    labels = load_labels(labels_path, legacy_hidden_path)
    label_of = {item_key(item): (labels.get(item_key(item)) or {}).get("label") for item in items}
    # "I know this" hides an item; items on a threat list always stay visible.
    visible = [item for item in items if item["threat"] or label_of[item_key(item)] != "known"]
    muted = [item for item in items if item not in visible]
    # Suspicious items stay on top.
    visible.sort(key=lambda item: label_of[item_key(item)] != "suspicious")
    columns = st.columns(4)
    columns[0].metric(tr("To check"), sum(not label_of[item_key(item)] for item in visible))
    columns[1].metric(tr("Suspicious"), sum(label == "suspicious" for label in label_of.values()))
    columns[2].metric(tr("On a threat list"), sum(item["threat"] for item in items))
    columns[3].metric(tr("Known"), len(muted))
    if not visible:
        st.success(tr("Nothing to check. Everything collected is under Details."))
    else:
        options = ["All", "Not marked", "Suspicious", "Threat lists", "Connections", "Name lookups"]
        choice = st.radio(tr("Show"), options, horizontal=True, format_func=tr, key="review_filter",
                          label_visibility="collapsed")
        tests = {"All": lambda item: True, "Not marked": lambda item: not label_of[item_key(item)],
                 "Suspicious": lambda item: label_of[item_key(item)] == "suspicious",
                 "Threat lists": lambda item: item["threat"], "Connections": lambda item: item["kind"] == "connection",
                 "Name lookups": lambda item: item["kind"] == "dns"}
        shown = [item for item in visible if tests[choice](item)]
        st.caption(tr("A flag means look, not danger. Most are normal programs. Mark each one: "
                      "I know this hides it next time, Suspicious keeps it on top."))
        for item in shown[:200]:
            _render_item(item, labels, labels_path, ip_owner)
        if len(shown) > 200:
            st.caption(tr("Showing the first 200. Details lists everything."))
    if muted and labels_path is not None:
        with st.expander(tr("Known ({count})", count=len(muted))):
            for item in muted:
                left, right = st.columns([4, 1])
                left.markdown(f"{item['title']} · {tr(item['label'])}")
                if right.button(tr("Show again"), key="unhide-" + item_key(item)):
                    try:
                        save_label(labels_path, item_key(item), None)
                    except OSError:
                        st.warning(tr("Could not save. Check the folder permissions."))
                    _rerun()
