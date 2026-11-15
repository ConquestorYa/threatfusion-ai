"""Explicit-language translation over the shared UI dictionary.

``threatfusion.i18n.tr`` reads the Streamlit session language; the API gets
the language from each request instead and uses the same dictionary, so both
interfaces word things identically.
"""
from __future__ import annotations

from typing import Literal

from ..i18n import _TR

Language = Literal["en", "tr"]

# English UI strings the React page needs; the server returns their translations.
UI_STRINGS = (
    "What to check",
    "Last {hours} hours · threat lists + unusual behavior · updates every 10 s",
    "To check",
    "Suspicious",
    "On a threat list",
    "Known",
    "Known ({count})",
    "Show",
    "All",
    "Not marked",
    "Threat lists",
    "Connections",
    "Name lookups",
    "A flag means look, not danger. Most are normal programs. Mark each one: "
    "I know this hides it next time, Suspicious keeps it on top.",
    "Nothing to check. Everything collected is under Details.",
    "Showing the first 200. Details lists everything.",
    "Why? What to do?",
    "✓ I know this",
    "? Not sure",
    "⚠ Suspicious",
    "🟣 Suspicious",
    "⚪ Not sure",
    "Click again to remove the mark",
    "Show again",
    "Could not save. Check the folder permissions.",
    "Look up on outside sites (opens in a new tab; the name or IP is sent to that site):",
    "This snapshot is older than one minute. Check whether the collector is still running.",
    "Some collected data is missing, so this list may be incomplete. Details shows why.",
    "Configure a local collector to show automatically collected connections.",
    "No collector snapshot yet. Start the local collector.",
    "Collector snapshot could not be read. Check private permissions and supported schema.",
    # Details tab
    "Details",
    "What does this page do?",
    "Show observed endpoint IPs locally; downloads keep aliases",
    "Show only connection reviews",
    "Include declared expected activity",
    "Connection investigation",
    "Select a connection group",
    "Select an observed device",
    "Select a queried domain",
    "Yes",
    "No",
    "Behavior score (ML)",
    # Quick lookup
    "Quick lookup",
    "Check one URL, domain or IP against your local threat intelligence without visiting it.",
    # Analyze telemetry
    "Analyze telemetry",
    # Setup & CTI updates
    "Setup & CTI updates",
    "Operating mode, your own API keys and threat-intelligence updates.",
    "Local settings could not be read. Check private file permissions.",
)


def translate(text: str, language: Language, **values: object) -> str:
    translated = _TR.get(text, text) if language == "tr" else text
    return translated.format(**values) if values else translated


def ui_strings(language: Language) -> dict[str, str]:
    return {text: translate(text, language) for text in UI_STRINGS}


def short_time(value) -> str:
    """A timestamp as local 'dd.mm HH:MM' (year added when it is not this year).

    Same reading as the review list (``ui_simple_review._clock``); raw ISO
    strings with seconds or microseconds never reach the page.
    """
    from datetime import datetime

    try:
        text = str(value).replace("Z", "+00:00").replace(" UTC", "+00:00")  # also format_timestamp output
        moment = datetime.fromisoformat(text).astimezone()
    except (TypeError, ValueError):
        return str(value) if value else "—"
    pattern = "%d.%m %H:%M" if moment.year == datetime.now().astimezone().year else "%d.%m.%Y %H:%M"
    return moment.strftime(pattern)


def evidence(text, language: Language) -> str:
    """Evidence labels translated one by one, keeping the full English text.

    One label contains the "; " separator itself; it is kept whole and
    translated as one unit (``ui_simple_review._SEMICOLON_LABEL``).
    """
    from ..ui_simple_review import _SEMICOLON_LABEL

    special = _SEMICOLON_LABEL[0]
    parts = str(text or "").replace(special, "\0").split("; ")
    return "; ".join(translate(special if part == "\0" else part, language) for part in parts if part)
