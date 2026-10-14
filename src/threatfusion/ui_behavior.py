"""Experimental ML tab of Collected connections: behavior-model hints beside the review list.

Reads the collector's records read-only, scores each (device, destination, port)
group of the last two 24-hour windows with the local behavior model and shows the
groups above the model's threshold with plain reasons. Nothing here changes the
collector, its review list or any threat-list result.
"""
from __future__ import annotations

import json
import sqlite3
from bisect import bisect_right
import time
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from .i18n import tr
from .ml_behavior import WINDOW_SECONDS, BehaviorModel, Connection, build_groups, reasons
from .ui_simple_review import _rerun, item_key, load_labels, lookup_links, save_label

MODEL_FILE = Path("ml") / "behavior-model.json"
REFRESH_SECONDS = 300
MAX_SHOWN = 20
MAX_TIMES = 500

REASONS = {
    "regular": "Repeats at steady intervals",
    "same_size": "Sends the same amount each time",
    "all_day": "Active most of the day",
    "no_name": "No website name (direct IP)",
    "rare_name": "Not a popular site",
    "failing": "Most attempts fail",
    "unusual_port": "Unusual port",
    "small": "Very small messages",
}

ADVICE = """1. **Do you recognize it?** Updaters, chat, music, cloud sync and games often check in at a steady rhythm. If you know the program, mark **I know this**.
2. **Which program is it?** While it is active, this command shows the program talking to that address (add `sudo` to see every program):
"""

GUIDE = """**What is this?** An experimental machine-learning model looks at *how* your devices talk to each destination, not at names or threat lists: how regularly connections repeat, how much is sent each time, how long they last, whether they fail, the port, and whether the destination had a website name and how random it looks. Malware that "calls home" often has a recognizable rhythm.

**How was it tested?** It learned from public research recordings of real malware and normal computers (Stratosphere Lab, Czech Technical University; Malware-Traffic-Analysis.net), plus a few days of this computer's own traffic. It was then tested once on recordings it had never seen.

**How to use it:** A high score is a reason to look, not proof. Updaters, chat apps and sync tools can look similar. Mark what you recognize; your marks help the next version. This tab does not change What to check."""

GUIDE_TR = """**Bu nedir?** Deneysel bir makine öğrenmesi modeli, cihazlarının her hedefle *nasıl* konuştuğuna bakar; adlara ya da tehdit listelerine değil: bağlantılar ne kadar düzenli tekrarlıyor, her seferinde ne kadar veri gidiyor, ne kadar sürüyor, başarısız oluyor mu, hangi port kullanılıyor, hedefin bir site adı var mı ve bu ad ne kadar rastgele görünüyor. "Eve telefon eden" zararlı yazılımların çoğunun tanınabilir bir ritmi vardır.

**Nasıl test edildi?** Gerçek zararlı yazılımların ve normal bilgisayarların herkese açık araştırma kayıtlarından (Stratosphere Lab, Çek Teknik Üniversitesi; Malware-Traffic-Analysis.net) ve bu bilgisayarın birkaç günlük kendi trafiğinden öğrendi. Sonra hiç görmediği kayıtlarda bir kez test edildi.

**Nasıl kullanılır?** Yüksek puan bakmak için bir sebeptir, kanıt değildir. Güncelleyiciler, sohbet ve eşitleme programları benzer görünebilir. Tanıdıklarını işaretle; işaretlerin bir sonraki sürümün daha iyi öğrenmesine yardım eder. Bu sekme Bakılacaklar listesini değiştirmez."""


def _guide() -> str:
    from .i18n import current_language
    return GUIDE_TR if current_language() == "tr" else GUIDE


def model_path(install_dir: Path) -> Path:
    return install_dir / MODEL_FILE


@st.cache_resource(show_spinner=False, max_entries=2)
def _load_model(path: str, modified: float) -> BehaviorModel:
    return BehaviorModel.load(Path(path))


@st.cache_resource(show_spinner=False, max_entries=2)
def _popular(db_path: str):
    from .popular_domains import load_popular_domains
    return load_popular_domains(Path(db_path))


def read_collector_records(db_path: Path) -> tuple[list[Connection], dict[str, set[str]]]:
    """Connections and DNS answers from the collector database, opened read-only."""
    connections, names = [], {}
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5) as db:
        for (payload,) in db.execute("SELECT payload FROM records WHERE kind='conn'"):
            row = json.loads(payload)
            if not row.get("timestamp") or not row.get("responder_ip"):
                continue
            connections.append(Connection(
                datetime.fromisoformat(row["timestamp"]).timestamp(), str(row.get("originator_ip") or ""),
                row["responder_ip"], row.get("responder_port"), str(row.get("protocol") or ""),
                row.get("duration_seconds"), row.get("originator_bytes"), row.get("responder_bytes"), row.get("state")))
        for (payload,) in db.execute("SELECT payload FROM records WHERE kind='dns'"):
            event = json.loads(payload).get("event") or {}
            name = str(event.get("query_name") or "").strip().rstrip(".").lower()
            for address in [event.get("response_ip"), *(event.get("response_ips") or ())]:
                if name and address:
                    names.setdefault(str(address), set()).add(name)
    return connections, names


@st.cache_data(show_spinner=False, max_entries=2, ttl=REFRESH_SECONDS * 2)
def score_groups(db_path: str, model_file: str, model_modified: float, cti_db: str | None, bucket: int) -> list[dict]:
    """Scored groups, highest first (recomputed at most every REFRESH_SECONDS)."""
    model = _load_model(model_file, model_modified)
    popular = _popular(cti_db) if cti_db else None
    if popular:
        from .popular_domains import is_popular

        def popular_name(name):
            return is_popular(name, popular)
    else:
        def popular_name(name):
            return False
    connections, names = read_collector_records(Path(db_path))
    times: dict[tuple, list[float]] = {}
    for c in connections:
        times.setdefault((c.originator, c.responder, c.port, c.protocol), []).append(c.timestamp)
    for values in times.values():
        values.sort()
    rows = []
    for group in build_groups(connections, names, popular_name):
        listed = sorted(names.get(group.responder, ()))
        own = times.get((group.originator, group.responder, group.port, group.protocol), [])
        start = bisect_right(own, group.window_end - WINDOW_SECONDS)
        rows.append({
            "times": own[start:bisect_right(own, group.window_end)][-MAX_TIMES:],
            "score": model.score(group.features), "device": group.originator, "address": group.responder,
            "port": group.port, "protocol": group.protocol, "name": listed[0] if listed else None, "names": listed,
            "connections": group.connections, "first": group.first_seen, "last": group.last_seen,
            "reasons": reasons(group.features),
        })
    # One row per destination: the strongest window.
    best = {}
    for row in sorted(rows, key=lambda r: -r["score"]):
        best.setdefault((row["device"], row["address"], row["port"], row["protocol"]), row)
    return list(best.values())


def level(score: float, threshold: float) -> str:
    """High: above the model's alarm line; Medium: most trees vote malicious; Low otherwise."""
    return "High" if score >= threshold else "Medium" if score >= 0.5 else "Low"


def scored(state_dir: Path | None, cti_db_path: Path | None = None) -> tuple[BehaviorModel, list[dict]] | None:
    """(model, scored groups) when a local model and collector data exist; None otherwise."""
    if state_dir is None:
        return None
    path = model_path(Path(state_dir).parent)
    database = Path(state_dir) / "collector.sqlite"
    if not path.exists() or not database.exists():
        return None
    try:
        modified = path.stat().st_mtime
        model = _load_model(str(path), modified)
        return model, score_groups(str(database), str(path), modified, str(cti_db_path) if cti_db_path else None,
                                   int(time.time() // REFRESH_SECONDS))
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        return None


def name_scores(result) -> dict[str, tuple[int, str]]:
    """Highest behavior score per DNS name: name -> (score 0-100, level)."""
    if result is None:
        return {}
    model, rows = result
    best: dict[str, float] = {}
    for row in rows:
        for name in row["names"]:
            best[name] = max(best.get(name, 0.0), row["score"])
    return {name: (round(score * 100), level(score, model.threshold)) for name, score in best.items()}


def _score_text(score: float, threshold: float) -> str:
    return f"{round(score * 100)}/100 · {tr(level(score, threshold))}"


def _clock(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).astimezone().strftime("%d.%m %H:%M")


def _ml_item(row) -> dict:
    return {"kind": "ml", "title": f"{row['name'] or row['address']}:{row['port']}"}


def _rhythm_chart(times: list[float]):
    """Each connection as a tick on a time line: malware check-ins look like an even comb."""
    import altair as alt
    import pandas as pd
    frame = pd.DataFrame({"time": [datetime.fromtimestamp(t) for t in times]})  # local clock, like the labels
    return (alt.Chart(frame).mark_tick(thickness=2, size=26)
            .encode(x=alt.X("time:T", title=None, axis=alt.Axis(format="%d.%m %H:%M", labelAngle=0, tickCount=6)))
            .properties(height=56))


def _render_card(row, model, labels, labels_path, ip_owner, key_prefix="ml"):
    item = _ml_item(row)
    current = (labels.get(item_key(item)) or {}).get("label")
    score = round(row["score"] * 100)
    with st.container(border=True):
        left, right = st.columns([3, 1])
        title = row["name"] or row["address"]
        badge = {"suspicious": " · " + tr("🟣 Suspicious"), "unsure": " · " + tr("⚪ Not sure")}.get(current, "")
        left.markdown(f"#### {title}{badge}")
        where = f"`{row['device']}` → `{row['address']}:{row['port']}/{row['protocol']}`"
        owner = ip_owner(row["address"]) if ip_owner else None
        left.markdown(where + (f" · {owner.label}" if owner else ""))
        right.metric(tr("Behavior score"), f"{score}/100", tr(level(row["score"], model.threshold)),
                     delta_color="off", delta_arrow="off")
        if row["reasons"]:
            st.markdown("**" + tr("Why it stands out") + ":** " + " · ".join(tr(REASONS[r]) for r in row["reasons"]))
        if row.get("times"):
            st.caption(tr("Connection rhythm · {count} connections, {first} – {last}", count=row["connections"],
                          first=_clock(row["first"]), last=_clock(row["last"])))
            st.altair_chart(_rhythm_chart(row["times"]), width="stretch")
        if labels_path is not None:
            buttons = st.container(horizontal=True, gap="small")
            for label, text in (("known", "✓ I know this"), ("unsure", "? Not sure"), ("suspicious", "⚠ Suspicious")):
                selected = current == label
                if buttons.button(tr(text), key=f"{key_prefix}-{label}-{item_key(item)}", type="primary" if selected else "secondary"):
                    try:
                        save_label(labels_path, item_key(item), None if selected else label)
                    except OSError:
                        st.warning(tr("Could not save. Check the folder permissions."))
                    _rerun()
        with st.expander(tr("What should I do?")):
            st.markdown(tr(ADVICE))
            st.code(f"ss -tunp dst {row['address']}", language="shell")
            links = lookup_links(row["name"], row["address"])
            if links:
                st.caption(tr("Opens in a new tab; the name or IP is sent to that site."))
                for column, (label, url) in zip(st.columns(len(links)), links):
                    column.link_button(label, url)


def _percent(value) -> str:
    return "–" if value is None else f"%{round(value * 100)}"


def render_behavior_tab(state_dir: Path, *, cti_db_path: Path | None = None, ip_owner=None) -> None:
    install_dir = state_dir.parent
    path = model_path(install_dir)
    st.caption(tr("Experimental · a machine-learning hint beside What to check, never a verdict"))
    from .ui_new_destinations import render_new_destinations
    render_new_destinations(state_dir, cti_db_path=cti_db_path, ip_owner=ip_owner)
    if not path.exists():
        st.markdown("### " + tr("Behavior model"))
        st.caption(tr("No behavior model on this computer yet. It is trained locally from public malware "
                      "recordings and this computer's own traffic, and is never downloaded from the internet."))
        return
    try:
        modified = path.stat().st_mtime
        model = _load_model(str(path), modified)
        rows = score_groups(str(state_dir / "collector.sqlite"), str(path), modified,
                            str(cti_db_path) if cti_db_path else None, int(time.time() // REFRESH_SECONDS))
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        st.warning(tr("The behavior model or the collected data could not be read right now."))
        return
    labels_path = install_dir / "review-labels.json"
    labels = load_labels(labels_path)
    evaluation = model.evaluation.get("eval", {})
    flagged = [r for r in rows if r["score"] >= model.threshold]
    hidden = [r for r in flagged if (labels.get(item_key(_ml_item(r))) or {}).get("label") == "known"]
    shown = [r for r in flagged if r not in hidden]
    shown.sort(key=lambda r: ((labels.get(item_key(_ml_item(r))) or {}).get("label") != "suspicious", -r["score"]))
    devices = len({r["device"] for r in rows})
    with st.container(border=True):
        if shown:
            st.markdown("### " + tr("{count} connection(s) stand out", count=len(shown)))
        else:
            st.markdown("### " + tr("Nothing unusual in how your devices talk"))
        st.caption(tr("In the last 48 hours the model checked how {devices} device(s) talked to {count} destination(s).",
                      devices=devices, count=len(rows)))
    columns = st.columns(4)
    columns[0].metric(tr("Stands out"), len(shown))
    columns[1].metric(tr("Destinations checked"), len(rows))
    columns[2].metric(tr("Caught in testing"), _percent(evaluation.get("malware_capture_recall")),
                      help=tr("Share of never-seen malware recordings in which the model flagged at least one connection."))
    columns[3].metric(tr("False flags per day (test)"), evaluation.get("normal_flagged_per_unit_day", "–"),
                      help=tr("Average flags per computer per day on never-seen normal computers."))
    for row in shown[:MAX_SHOWN]:
        _render_card(row, model, labels, labels_path, ip_owner)
    if hidden:
        st.caption(tr("{count} you marked as known are hidden.", count=len(hidden)))
    below = [r for r in rows if r["score"] < model.threshold][:10]
    if below:
        with st.expander(tr("Highest scores below the line")):
            st.dataframe([{tr("Destination"): r["name"] or r["address"], tr("Port"): r["port"],
                           tr("Score"): _score_text(r["score"], model.threshold),
                           tr("Why"): ", ".join(tr(REASONS[x]) for x in r["reasons"])} for r in below],
                         hide_index=True, width="stretch")
    with st.expander(tr("What is this?")):
        st.markdown(_guide())
        grade = model.evaluation.get("grade", "")
        st.caption(tr("Model {model} · trained {time} · test grade: {grade}", model=model.model_id or "?",
                      time=model.trained_at or "?", grade=grade.split(":")[0]))


def render_behavior_evaluation(install_dir: Path) -> None:
    """Model evaluation page for the local behavior model: what was measured, and its limits."""
    path = model_path(install_dir)
    try:
        model = _load_model(str(path), path.stat().st_mtime)
    except (OSError, ValueError, KeyError, TypeError):
        st.warning(tr("The behavior model could not be read."))
        return
    report = model.evaluation
    test, dev = report.get("eval", {}), report.get("dev", {})
    st.markdown("### " + tr("Experimental behavior model"))
    st.caption(tr("Model {model} · trained {time} · test grade: {grade}", model=model.model_id or "?",
                  time=model.trained_at or "?", grade=str(report.get("grade", "")).split(":")[0]))
    columns = st.columns(4)
    columns[0].metric(tr("Caught in testing"), _percent(test.get("malware_capture_recall")))
    columns[1].metric(tr("Malicious connections caught"), _percent(test.get("malware_group_recall")))
    columns[2].metric(tr("False flags per day (test)"), test.get("normal_flagged_per_unit_day", "–"))
    columns[3].metric(tr("Score line"), round(model.threshold * 100))
    checks = report.get("checks", {})
    if checks:
        if report.get("pass"):
            st.success(tr("Passed its declared test: at least half of never-seen malware recordings caught, "
                          "at most one false flag per computer per day."))
        else:
            st.warning(tr("Did not pass every declared test; treat its hints with extra care."))
    rows = []
    for title, values in ((tr("Never-seen test recordings"), test), (tr("Development recordings"), dev)):
        rows.append({tr("Data"): title,
                     tr("Malware recordings"): values.get("malware_captures"),
                     tr("Caught"): _percent(values.get("malware_capture_recall")),
                     tr("Normal computer-days"): values.get("normal_unit_days"),
                     tr("False flags per day"): values.get("normal_flagged_per_unit_day")})
    st.dataframe(rows, hide_index=True, width="stretch")
    importance = report.get("importance") or []
    if importance:
        from .i18n import current_language
        names = FEATURE_NAMES_TR if current_language() == "tr" else FEATURE_NAMES
        st.markdown("**" + tr("What the model looks at most") + "**")
        st.bar_chart({names.get(f, f): v for f, v in importance[:10]}, horizontal=True)
    st.markdown("**" + tr("Limits") + "**")
    st.markdown(tr(LIMITS))
    with st.expander(tr("What is this?")):
        st.markdown(_guide())


FEATURE_NAMES = {
    "log_connections": "Number of connections", "log_span": "Time span", "active_hours": "Active hours",
    "log_interval_median": "Typical gap between connections", "interval_cv": "Gap variation",
    "interval_regular_share": "Steady rhythm", "interval_mad_ratio": "Gap spread",
    "log_out_bytes_median": "Bytes sent", "log_in_bytes_median": "Bytes received",
    "out_bytes_cv": "Sent-size variation", "in_bytes_cv": "Received-size variation",
    "out_bytes_mode_share": "Same size each time", "log_duration_median": "Connection length",
    "duration_cv": "Length variation", "failed_share": "Failed attempts", "empty_share": "Empty connections",
    "log_bytes_ratio": "Sent vs received", "port_web": "Web port",
    "port_low": "System port", "protocol_udp": "UDP", "has_name": "Has a website name",
    "log_rate": "Connections per hour", "name_entropy": "Random-looking name", "name_digit_share": "Digits in name",
}
FEATURE_NAMES_TR = {
    "log_connections": "Bağlantı sayısı", "log_span": "Zaman aralığı", "active_hours": "Aktif saatler",
    "log_interval_median": "Bağlantılar arası tipik süre", "interval_cv": "Süre değişkenliği",
    "interval_regular_share": "Düzenli ritim", "interval_mad_ratio": "Süre dağılımı",
    "log_out_bytes_median": "Gönderilen veri", "log_in_bytes_median": "Alınan veri",
    "out_bytes_cv": "Gönderim boyutu değişkenliği", "in_bytes_cv": "Alım boyutu değişkenliği",
    "out_bytes_mode_share": "Her seferinde aynı boyut", "log_duration_median": "Bağlantı süresi",
    "duration_cv": "Süre değişkenliği (bağlantı)", "failed_share": "Başarısız denemeler",
    "empty_share": "Boş bağlantılar", "log_bytes_ratio": "Gönderilen / alınan", "port_web": "Web portu",
    "port_low": "Sistem portu", "protocol_udp": "UDP", "has_name": "Site adı var",
    "log_rate": "Saatteki bağlantı", "name_entropy": "Rastgele görünen ad", "name_digit_share": "Addaki rakamlar",
}
LIMITS = """- The malware recordings are lab infections from 2011–2024; new malware can behave differently.
- Some connections in those recordings are ordinary background traffic, so the labels are approximate.
- This computer's own traffic was assumed to be normal and covers only a few days. A stricter check on new days of this computer's traffic is running.
- A group needs at least 4 connections to the same destination within a day; single or rare connections are not scored."""


def render_lookup_behavior(name: str | None, address: str | None, state_dir: Path | None,
                           cti_db_path: Path | None = None) -> None:
    """Quick lookup: how this computer talked to the looked-up name or IP (no network, local data only)."""
    result = scored(state_dir, cti_db_path)
    if result is None:
        return
    model, rows = result
    wanted = (name or "").strip().rstrip(".").lower()
    matches = [r for r in rows if (address and r["address"] == address)
               or (wanted and any(n == wanted or n.endswith("." + wanted) for n in r["names"]))]
    st.markdown("**" + tr("Behavior on this computer (experimental ML)") + "**")
    if not matches:
        st.caption(tr("This computer did not talk to it often enough in the last 48 hours for a behavior score "
                      "(at least 4 connections to the same destination are needed)."))
        return
    labels = load_labels(Path(state_dir).parent / "review-labels.json")
    for row in sorted(matches, key=lambda r: -r["score"])[:3]:
        _render_card(row, model, labels, Path(state_dir).parent / "review-labels.json", None, key_prefix="lookup-ml")
