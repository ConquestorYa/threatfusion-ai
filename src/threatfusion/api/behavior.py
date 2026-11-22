"""The collector's "Experimental ML" tab, its DNS score column and the Quick
lookup behavior card as JSON.

Every value comes from the Streamlit code paths: ``ui_new_destinations``
(new rhythmic destinations and their private baseline), ``ui_behavior``
(on-device behavior model: learning, scoring, levels, reasons, the
evaluation figures) and ``ui_simple_review`` (marks, outside lookup links).
Like the Streamlit tab, opening this screen keeps the local learning going
(``ui_behavior.learn``/``scored``): it stores complete days of this
computer's groups and trains when due. Nothing is sent anywhere and nothing
changes the collector, its review list or threat-list results.

``ui_behavior`` and ``ui_new_destinations`` translate with ``tr``, which reads
the Streamlit session language; ``lookup.in_language`` sets the language of
one response instead, so both interfaces word things identically.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from .. import i18n
from .i18n import short_time
from .lookup import in_language
from .review import _owner_lookup, _write_lock, labels_path
from .settings import ApiSettings

_ERRORS = (OSError, ValueError, KeyError, TypeError, sqlite3.Error)
MAX_LOOKUP_CARDS = 3


class NotAvailable(LookupError):
    """No collector configured for this screen."""


def _bucket(module) -> int:
    return int(time.time() // module.REFRESH_SECONDS)


def _cti(settings: ApiSettings) -> str | None:
    return str(settings.cti_db_path) if settings.cti_db_path else None


def _mark_of(labels: dict, key: str) -> str | None:
    return (labels.get(key) or {}).get("label")


def _card(row, *, kind: str, key: str, mark: str | None, shown_mark: str | None, ip_owner,
          score_label: str, score: str, level: str | None, why_label: str, why: list[str],
          others: str | None = None) -> dict:
    """One Streamlit card (``ui_behavior._render_card`` / ``ui_new_destinations._card``)."""
    from ..ui_behavior import ADVICE, _clock
    from ..ui_simple_review import lookup_links

    tr = i18n.tr
    owner = ip_owner(row["address"]) if ip_owner else None
    return {
        "key": key,
        "kind": kind,
        "title": row["name"] or row["address"],
        "mark": mark,
        "shown_mark": shown_mark,
        "device": row["device"],
        "destination": f"{row['address']}:{row['port']}/{row['protocol']}",
        "owner": owner.label if owner else None,
        "others": others,
        "score_label": score_label,
        "score": score,
        "level": level,
        "why_label": why_label,
        "why": why,
        "rhythm": {"caption": tr("Connection rhythm · {count} connections, {first} – {last}", count=row["connections"],
                                 first=_clock(row["first"]), last=_clock(row["last"])),
                   "times": [round(value, 3) for value in row["times"]]} if row.get("times") else None,
        "advice_title": tr("What should I do?"),
        "advice": tr(ADVICE),
        "command": f"ss -tunp dst {row['address']}",
        "links_caption": tr("Opens in a new tab; the name or IP is sent to that site."),
        "links": [{"name": name, "url": url} for name, url in lookup_links(row["name"], row["address"])],
    }


def _ml_card(row, model, labels: dict, ip_owner) -> dict:
    from ..ui_behavior import REASONS, _ml_item, level
    from ..ui_simple_review import item_key

    tr = i18n.tr
    key = item_key(_ml_item(row))
    mark = _mark_of(labels, key)
    return _card(row, kind="ml", key=key, mark=mark, shown_mark=mark, ip_owner=ip_owner,
                 score_label=tr("Behavior score"), score=f"{round(row['score'] * 100)}/100",
                 level=tr(level(row["score"], model.threshold)), why_label=tr("Why it stands out"),
                 why=[tr(REASONS[reason]) for reason in row["reasons"]])


def _new_section(state_dir: Path, settings: ApiSettings, labels: dict, ip_owner) -> dict:
    """``ui_new_destinations.render_new_destinations``."""
    from ..ui_new_destinations import (
        BASELINE_FILE,
        MAX_SHOWN,
        _every,
        _guide,
        _item,
        _registrable,
        marked_sites,
        new_destinations,
    )
    from .. import ui_new_destinations
    from ..ui_simple_review import item_key

    tr = i18n.tr
    section = {"title": tr("New for this computer"), "guide_title": tr("What is this?"), "guide": _guide(),
               "cards": [], "captions": [], "notice": None}
    database = state_dir / "collector.sqlite"
    if not database.exists():
        return section | {"state": "no_data", "empty": tr("No collected connections yet.")}
    try:
        result = new_destinations(str(database), str(state_dir.parent / BASELINE_FILE), _cti(settings),
                                  _bucket(ui_new_destinations))
    except _ERRORS:
        return section | {"state": "unreadable", "warning": tr("The collected data could not be read right now.")}
    rows = result["rows"]
    known_sites, suspicious_sites = marked_sites(labels, _registrable(_cti(settings)))

    def mark(row):
        own = _mark_of(labels, item_key(_item(row)))
        if own:
            return own
        if row.get("domain") in known_sites:
            return "known_site"
        return "suspicious" if row.get("domain") in suspicious_sites else None

    hidden = [r for r in rows if mark(r) == "known"]
    hidden_by_site = [r for r in rows if mark(r) == "known_site"]
    shown = [r for r in rows if mark(r) not in ("known", "known_site")]
    shown.sort(key=lambda r: (mark(r) != "suspicious", -r["score"]))
    summary, notice, captions = None, None, []
    if shown:
        summary = tr("{count} new destination(s) called at a steady rhythm in the last 48 hours.", count=len(shown))
    elif result["learning"]:
        notice = {"kind": "info", "text": tr("Learning what is normal for this computer. New destinations are shown "
                                             "after 3 days of history while ThreatFusion is open.")}
        if len(result["learning"]) < result["devices"]:
            summary = tr("{count} of {devices} device(s) have enough history.",
                         count=result["devices"] - len(result["learning"]), devices=result["devices"])
    else:
        notice = {"kind": "success", "text": tr("No new destination is calling at a steady rhythm.")}
    cards = []
    for row in shown[:MAX_SHOWN]:
        key = item_key(_item(row))
        own = _mark_of(labels, key)
        others = (tr("Also {count} other address(es) of the same site: {addresses}", count=len(row["others"]),
                     addresses=", ".join(row["others"][:5])) if row.get("others") else None)
        cards.append(_card(
            row, kind="new", key=key, mark=own,
            shown_mark=own or ("suspicious" if row.get("domain") in suspicious_sites else None), ip_owner=ip_owner,
            score_label=tr("Rhythm"), score=f"{round(row['score'] * 100)}/100", level=None,
            why_label=tr("Why it is listed"),
            why=[tr("First time seen on this computer"), tr("Repeats {every}", every=_every(row["interval"])),
                 tr("{count} connections", count=row["connections"])], others=others))
    if hidden:
        captions.append(tr("{count} you marked as known are hidden.", count=len(hidden)))
    if hidden_by_site:
        captions.append(tr("{count} hidden because you marked the same site as known elsewhere.", count=len(hidden_by_site)))
    return section | {"state": "ok", "summary": summary, "notice": notice, "cards": cards, "captions": captions}


def _learn(state_dir: Path, settings: ApiSettings) -> dict | None:
    """Store complete days and train when due (outside the language lock: training can take a while)."""
    from .. import ui_behavior

    database = state_dir / "collector.sqlite"
    if not database.exists():
        return None
    return ui_behavior.learn(str(database), str(state_dir.parent), _cti(settings), _bucket(ui_behavior))


def _model_section(state_dir: Path, settings: ApiSettings, labels: dict, ip_owner, learning: dict | None) -> dict:
    """The behavior-model half of ``ui_behavior.render_behavior_tab``."""
    from .. import ml_local, ui_behavior
    from ..ui_behavior import (
        MAX_SHOWN,
        REASONS,
        _guide,
        _load_model,
        _ml_item,
        _percent,
        _score_text,
        model_path,
        score_groups,
    )
    from ..ui_simple_review import item_key

    tr = i18n.tr
    path = model_path(state_dir.parent)
    database = state_dir / "collector.sqlite"
    if not path.exists():
        captions = []
        if learning and learning.get("available"):
            captions.append(tr("The model is learning what is normal for this computer: {days} of {needed} days collected. "
                               "It then trains here, on public malware examples plus these days, and never sends anything out.",
                               days=learning["days"], needed=ml_local.LEARNING_DAYS))
        else:
            captions.append(tr("No behavior model is available in this installation."))
        if learning and learning.get("error"):
            captions.append(tr("Training failed: {error}", error=learning["error"]))
        return {"state": "learning", "title": tr("Behavior model"), "captions": captions}
    try:
        modified = path.stat().st_mtime
        model = _load_model(str(path), modified)
        rows = score_groups(str(database), str(path), modified, _cti(settings), _bucket(ui_behavior))
    except _ERRORS:
        return {"state": "unreadable", "title": tr("Behavior model"),
                "warning": tr("The behavior model or the collected data could not be read right now.")}
    evaluation = model.evaluation.get("eval", {})
    flagged = [r for r in rows if r["score"] >= model.threshold]
    hidden = [r for r in flagged if _mark_of(labels, item_key(_ml_item(r))) == "known"]
    shown = [r for r in flagged if r not in hidden]
    shown.sort(key=lambda r: (_mark_of(labels, item_key(_ml_item(r))) != "suspicious", -r["score"]))
    devices = len({r["device"] for r in rows})
    below = [r for r in rows if r["score"] < model.threshold][:10]
    return {
        "state": "ok",
        "title": tr("Behavior model"),
        "heading": tr("{count} connection(s) stand out", count=len(shown)) if shown
        else tr("Nothing unusual in how your devices talk"),
        "summary": tr("In the last 48 hours the model checked how {devices} device(s) talked to {count} destination(s).",
                      devices=devices, count=len(rows)),
        "metrics": [
            {"label": tr("Stands out"), "value": len(shown)},
            {"label": tr("Destinations checked"), "value": len(rows)},
            {"label": tr("Caught in testing"), "value": _percent(evaluation.get("malware_capture_recall")),
             "help": tr("Share of never-seen malware recordings in which the model flagged at least one connection.")},
            {"label": tr("False flags per day (test)"), "value": evaluation.get("normal_flagged_per_unit_day", "–"),
             "help": tr("Average flags per computer per day on never-seen normal computers.")},
        ],
        "cards": [_ml_card(row, model, labels, ip_owner) for row in shown[:MAX_SHOWN]],
        "captions": [tr("{count} you marked as known are hidden.", count=len(hidden))] if hidden else [],
        "below": {"title": tr("Highest scores below the line"), "columns": [
            tr("Destination"), tr("Port"), tr("Score"), tr("Why")],
            "rows": [[r["name"] or r["address"], r["port"], _score_text(r["score"], model.threshold),
                      ", ".join(tr(REASONS[x]) for x in r["reasons"])] for r in below]} if below else None,
        "guide_title": tr("What is this?"),
        "guide": _guide(),
        "model_caption": model_caption(model),
    }


def model_caption(model) -> str:
    """"Model … · trained … · test grade …" with a short local time instead of the raw ISO string."""
    tr = i18n.tr
    grade = str(model.evaluation.get("grade", "")).split(":")[0]
    return tr("Model {model} · trained {time} · test grade: {grade}", model=model.model_id or "?",
              time=short_time(model.trained_at) if model.trained_at else "?", grade=tr(grade))


def behavior_response(settings: ApiSettings, language: str) -> dict:
    """``ui_behavior.render_behavior_tab``: new destinations, then the behavior model."""
    from ..ui_simple_review import load_labels

    if not settings.collector_available or settings.state_dir is None:
        return {"state": "not_configured"}
    state_dir = Path(settings.state_dir)
    learning = _learn(state_dir, settings)
    with in_language(language):
        labels = load_labels(labels_path(state_dir))
        ip_owner = _owner_lookup(settings.cti_db_path)
        return {
            "state": "ok",
            "caption": i18n.tr("Experimental · a machine-learning hint beside What to check, never a verdict"),
            "new": _new_section(state_dir, settings, labels, ip_owner),
            "model": _model_section(state_dir, settings, labels, ip_owner, learning),
        }


def dns_scores(settings: ApiSettings) -> dict[str, tuple[int, str]]:
    """``ui_behavior.name_scores(scored(...))`` for the Details DNS table (empty without a model)."""
    from ..ui_behavior import name_scores

    return name_scores(scored_rows(settings))


def scored_rows(settings: ApiSettings):
    """``ui_behavior.scored``: (model, rows) or None. Call outside ``in_language`` (it may train)."""
    from ..ui_behavior import scored

    if not settings.collector_available or settings.state_dir is None:
        return None
    try:
        return scored(Path(settings.state_dir), settings.cti_db_path)
    except _ERRORS:
        return None


def lookup_behavior(settings: ApiSettings, result, name: str | None, address: str | None) -> dict | None:
    """``ui_behavior.render_lookup_behavior`` for ``scored_rows`` (inside ``in_language``); None without a model."""
    from ..ui_simple_review import load_labels

    if result is None:
        return None
    model, rows = result
    tr = i18n.tr
    wanted = (name or "").strip().rstrip(".").lower()
    matches = [r for r in rows if (address and r["address"] == address)
               or (wanted and any(n == wanted or n.endswith("." + wanted) for n in r["names"]))]
    block = {"title": tr("Behavior on this computer (experimental ML)"), "cards": [], "empty": None}
    if not matches:
        return block | {"empty": tr("This computer did not talk to it often enough in the last 48 hours for a behavior "
                                    "score (at least 4 connections to the same destination are needed).")}
    labels = load_labels(labels_path(Path(settings.state_dir)))
    return block | {"cards": [_ml_card(row, model, labels, None)
                              for row in sorted(matches, key=lambda r: -r["score"])[:MAX_LOOKUP_CARDS]]}


class UnknownCard(LookupError):
    """The key is not a card this screen or Quick lookup can show now."""


def set_mark(settings: ApiSettings, key: str, mark: str | None) -> None:
    """Mark a behavior or new-destination card; only keys of current rows are written."""
    from .. import ui_new_destinations
    from ..ui_behavior import _ml_item
    from ..ui_new_destinations import BASELINE_FILE, _item, new_destinations
    from ..ui_simple_review import item_key, save_label

    if not settings.collector_available or settings.state_dir is None:
        raise UnknownCard(key)
    state_dir = Path(settings.state_dir)
    keys: set[str] = set()
    if key.startswith("ml:"):
        result = scored_rows(settings)
        keys = {item_key(_ml_item(row)) for row in result[1]} if result else set()
    elif key.startswith("new:") and (state_dir / "collector.sqlite").exists():
        rows = new_destinations(str(state_dir / "collector.sqlite"), str(state_dir.parent / BASELINE_FILE),
                                _cti(settings), _bucket(ui_new_destinations))["rows"]
        keys = {item_key(_item(row)) for row in rows}
    if key not in keys:
        raise UnknownCard(key)
    with _write_lock:
        save_label(labels_path(state_dir), key, mark)
