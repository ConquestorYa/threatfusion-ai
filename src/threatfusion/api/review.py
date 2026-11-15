"""The "What to check" list as JSON, built by the same code as the Streamlit tab.

Nothing here re-implements the evidence logic: items come from
``build_review_items``, marks from ``load_labels``/``save_label`` and the
snapshot from the validated private reader. This module only shapes the
result for a browser and applies the same visibility rules.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Literal

from .i18n import Language, translate
from .settings import ApiSettings

Mark = Literal["known", "unsure", "suspicious"]
# Bounds the response; counts always cover every item.
MAX_VISIBLE_ITEMS = 2_000
MAX_KNOWN_ITEMS = 2_000
STALE_AFTER_SECONDS = 60

_write_lock = threading.Lock()


def labels_path(state_dir: Path) -> Path:
    return state_dir.parent / "review-labels.json"


def _legacy_hidden_path(state_dir: Path) -> Path:
    return state_dir.parent / "review-hidden.json"


@lru_cache(maxsize=4)
def _owner_reader(db_path: str):
    from ..ip_owners import IPOwnerReader

    return IPOwnerReader(Path(db_path))


def _owner_lookup(cti_db_path: Path | None):
    """IP owner names from the local table; looked up again until it exists."""
    if cti_db_path is None:
        return None
    reader = _owner_reader(str(cti_db_path))
    if not reader:
        _owner_reader.cache_clear()
        return None
    return reader.lookup


def _show(value, language: Language) -> str:
    text = str(value or "")
    if text.startswith("Host "):
        return translate("Host {number}", language, number=text[5:])
    if text.startswith("Device "):
        return translate("Device {number}", language, number=text[7:])
    return text


def _read(state_dir: Path):
    """Validated snapshot plus the local identity view (real IPs) when available.

    The Streamlit tab shows ``local_view or payload``: real addresses of the
    user's own network on this screen, aliases when the mapping is unusable.
    """
    from ..collector_identity import local_identity_view
    from ..ui_collector import read_snapshot

    payload = read_snapshot(state_dir)
    try:
        view = local_identity_view(state_dir, payload)
    except (OSError, ValueError, TypeError, KeyError):
        view = None
    return payload, view or payload


def _item_json(item, mark, language: Language, ip_owner) -> dict:
    from ..ui_simple_review import ADVICE, _address_of, item_key, lookup_links

    address = _address_of(item)
    owner = ip_owner(address) if ip_owner and address else None
    where = item.get("where")
    destination = None
    if where and where[0] == "address":
        destination = {"host": _show(where[1], language), "port": where[2]}
    facts = []
    if item["also"]:
        facts.append(translate("Same addresses as: {names}", language, names=", ".join(item["also"])))
    if item.get("sources"):
        facts.append(translate("Lists: {sources}", language, sources=", ".join(item["sources"])))
    target = item["title"] if not str(item["title"]).startswith(("Host ", "Device ")) else None
    metric_text, metric_values = item["metric"]
    return {
        "key": item_key(item),
        "kind": item["kind"],
        "threat": bool(item["threat"]),
        "title": _show(item["title"], language) if item["unnamed"] else str(item["title"]),
        "label": translate(item["label"], language),
        "metric": translate(metric_text, language, **metric_values),
        "devices": list(dict.fromkeys(_show(d, language) for d in item["devices"] if d)),
        "destination": destination,
        "owner": owner.label if owner else None,
        "when": item["when"],
        "what": [translate(sentence, language) for sentence in item["what"]],
        "advice": translate(ADVICE[item["advice"]], language),
        "facts": facts,
        "links": [{"name": name, "url": url} for name, url in lookup_links(target, address)],
        "mark": mark,
    }


def review_response(settings: ApiSettings, language: Language, *, now: datetime | None = None) -> dict:
    from ..ui_simple_review import build_review_items, item_key, load_labels

    if not settings.collector_available or settings.state_dir is None:
        return {"state": "not_configured"}
    state_dir = settings.state_dir
    try:
        payload, view = _read(state_dir)
    except FileNotFoundError:
        return {"state": "no_snapshot"}
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        return {"state": "unreadable"}
    status, counts = payload["collector"], payload["collector"]["counts"]
    now = now or datetime.now(timezone.utc)
    updated = datetime.fromisoformat(status["updated_at"])

    items = build_review_items(view)
    labels = load_labels(labels_path(state_dir), _legacy_hidden_path(state_dir))
    mark_of = {item_key(item): (labels.get(item_key(item)) or {}).get("label") for item in items}
    # Same rules as the Streamlit list: "I know this" hides an item unless it is
    # on a threat list, and items marked suspicious stay on top.
    visible = [item for item in items if item["threat"] or mark_of[item_key(item)] != "known"]
    known = [item for item in items if not (item["threat"] or mark_of[item_key(item)] != "known")]
    visible.sort(key=lambda item: mark_of[item_key(item)] != "suspicious")

    ip_owner = _owner_lookup(settings.cti_db_path)
    return {
        "state": "ok",
        "updated_at": status["updated_at"],
        "window_hours": status.get("window_seconds", 86400) // 3600,
        "stale": (now - updated).total_seconds() > STALE_AFTER_SECONDS,
        "coverage_incomplete": bool(counts["rejected_files"] or status.get("capacity_coverage_loss")
                                    or status.get("input_coverage_loss")),
        "counts": {
            "to_check": sum(not mark_of[item_key(item)] for item in visible),
            "suspicious": sum(mark == "suspicious" for mark in mark_of.values()),
            "threat": sum(bool(item["threat"]) for item in items),
            "known": len(known),
        },
        "items": [_item_json(item, mark_of[item_key(item)], language, ip_owner)
                  for item in visible[:MAX_VISIBLE_ITEMS]],
        "items_truncated": len(visible) > MAX_VISIBLE_ITEMS,
        "known": [{"key": item_key(item), "title": _show(item["title"], language) if item["unnamed"]
                   else str(item["title"]), "label": translate(item["label"], language)}
                  for item in known[:MAX_KNOWN_ITEMS]],
    }


class UnknownItem(LookupError):
    """The key is not an item of the current list."""


def set_mark(settings: ApiSettings, key: str, mark: Mark | None) -> None:
    """Mark an item of the current list; only keys the list shows can be written."""
    from ..ui_simple_review import build_review_items, item_key, save_label

    if not settings.collector_available or settings.state_dir is None:
        raise UnknownItem(key)
    _payload, view = _read(settings.state_dir)
    if key not in {item_key(item) for item in build_review_items(view)}:
        raise UnknownItem(key)
    with _write_lock:
        save_label(labels_path(settings.state_dir), key, mark)
