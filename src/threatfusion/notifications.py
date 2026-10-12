"""Desktop notification when collected traffic matches a threat list.

Only threat-list matches notify (never behavior reviews), each at most once.
Notifications can appear on a lock screen, so they name a domain only when the
traffic itself named one and never show an IP address. Linux `notify-send`
only; without it, or without a desktop session, nothing happens.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

NOTIFIED_FILE = "notified-threats.json"
LANGUAGE_FILE = "ui-language"  # last language chosen in the web app, beside NOTIFIED_FILE
MAX_KEYS = 2000
MAX_NAMES_IN_BODY = 3
_THREAT_LABELS = ("Exact known-domain IOC match", "Response IP matches known threat infrastructure",
                  "Response IPv6 address falls within a known threat network")

LABELS_FILE = "review-labels.json"  # written by the web app's review list, beside NOTIFIED_FILE

_TEXT = {
    "en": ("ThreatFusion: threat list match", "{count} new: {names}", "an address", "Open Collected connections."),
    "tr": ("ThreatFusion: tehdit listesi eşleşmesi", "{count} yeni: {names}", "bir adres", "Toplanan bağlantılar'ı aç."),
}
_SUSPICIOUS_TITLE = {"en": "ThreatFusion: seen again (you marked it suspicious)",
                     "tr": "ThreatFusion: yeniden görüldü (şüpheli işaretlemiştin)"}


def threat_alerts(payload: dict) -> dict[str, str | None]:
    """Stable key -> domain name to show (None: no name, an address only)."""
    alerts: dict[str, str | None] = {}
    for row in payload.get("findings", ()):
        if row.get("CTI match") is not True:
            continue
        names = [n for n in str(row.get("DNS names") or "").split(", ") if n]
        key = f"conn:{names[0]}" if names else f"conn:{row.get('Responder')}:{row.get('Responder port')}:{row.get('First observed')}"
        alerts[key] = names[0] if names else None
    for row in (payload.get("dns") or {}).get("report", {}).get("findings", ()):
        evidence = str(row.get("Evidence") or "")
        if row.get("Queue priority") == "Investigate" or any(label in evidence for label in _THREAT_LABELS):
            alerts[f"dns:{row.get('Target')}"] = row.get("Target")
    return alerts


def suspicious_alerts(payload: dict, labels_path: Path) -> dict[str, str]:
    """Names the user marked suspicious that appear again after the mark; once per name per day."""
    try:
        labels = json.loads(labels_path.read_text()).get("labels", {})
    except (OSError, ValueError, AttributeError):
        return {}
    marked = {}
    for key, entry in labels.items() if isinstance(labels, dict) else ():
        kind, _, name = str(key).partition(":")
        if (kind in ("dns", "connection") and isinstance(entry, dict) and entry.get("label") == "suspicious"
                and name and not name.startswith(("Host ", "Device "))):
            marked[name] = str(entry.get("at") or "")
    alerts = {}
    rows = [(n, row.get("Last observed")) for row in payload.get("findings", ())
            for n in str(row.get("DNS names") or "").split(", ") if n]
    rows += [(row.get("Target"), row.get("Last observed"))
             for row in (payload.get("dns") or {}).get("report", {}).get("findings", ())]
    for name, last in rows:
        last = str(last or "")
        if name in marked and last > marked[name]:
            alerts[f"suspicious:{name}:{last[:10]}"] = name
    return alerts


def _language(folder: Path | None = None) -> str:
    if folder is not None:
        try:
            chosen = (folder / LANGUAGE_FILE).read_text()[:8].strip()
        except OSError:
            chosen = ""
        if chosen in _TEXT:
            return chosen
    value = os.environ.get("LC_ALL") or os.environ.get("LC_MESSAGES") or os.environ.get("LANG") or ""
    return "tr" if value.casefold().startswith("tr") else "en"


def remember_language(folder: Path, language: str) -> None:
    """Called by the web app so notifications use the language the user reads."""
    if language not in _TEXT:
        return
    path = folder / LANGUAGE_FILE
    try:
        if path.read_text().strip() == language:
            return
    except OSError:
        pass
    descriptor, temporary = tempfile.mkstemp(dir=folder, prefix=".ui-language-")
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(language)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def desktop_available() -> bool:
    return bool(shutil.which("notify-send")) and bool(
        os.environ.get("DBUS_SESSION_BUS_ADDRESS") or os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"))


def _load(path: Path) -> list[str]:
    try:
        values = json.loads(path.read_text()).get("notified", [])
    except (OSError, ValueError, AttributeError):
        return []
    return [v for v in values if isinstance(v, str)]


def _save(path: Path, keys: list[str]) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".notified-")
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump({"schema_version": 1, "notified": keys[-MAX_KEYS:]}, handle)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def message(names: list[str | None], language: str = "en") -> tuple[str, str]:
    title, body, unnamed, hint = _TEXT[language]
    shown = list(dict.fromkeys(n or unnamed for n in names))
    text = ", ".join(shown[:MAX_NAMES_IN_BODY]) + (" …" if len(shown) > MAX_NAMES_IN_BODY else "")
    return title, body.format(count=len(names), names=text) + "\n" + hint


def notify_new_threats(payload: dict, state_path: Path, *, send=None) -> int:
    """Notify once per new threat-list match (and per suspicious-marked name seen again
    that day); returns how many were new."""
    groups = [(None, threat_alerts(payload)),
              (_SUSPICIOUS_TITLE, suspicious_alerts(payload, state_path.parent / LABELS_FILE))]
    known = set(_load(state_path))
    fresh = [(title, {k: v for k, v in alerts.items() if k not in known}) for title, alerts in groups]
    new = [key for _, alerts in fresh for key in alerts]
    if not new:
        return 0
    if send is None:
        if not desktop_available():
            return 0
        send = _send
    language = _language(state_path.parent)
    for titles, alerts in fresh:
        if alerts:
            title, body = message(list(alerts.values()), language)
            send(titles[language] if titles else title, body)
    # Recorded even when sending failed: one attempt per match, never a retry every poll.
    _save(state_path, _load(state_path) + new)
    return len(new)


def _send(title: str, body: str) -> bool:
    try:
        result = subprocess.run(["notify-send", "--app-name=ThreatFusion", "--urgency=critical", title, body],
                                timeout=5, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0
