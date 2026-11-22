"""Quick lookup as JSON, built with the Streamlit page's own helpers.

``ui_quick_lookup`` translates inside its presentation helpers with ``tr``;
``in_language`` sets the language of one response (a context variable, so
concurrent requests do not interfere). The analysis is ``analyze_quick_lookup_from_cache``.
The experimental "Behavior on this computer" card comes from
``behavior.lookup_behavior`` (``ui_behavior.render_lookup_behavior``); its
scoring (which may train) runs before the language lock is taken.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from pathlib import Path

from .. import i18n
from .settings import ApiSettings

_AGES: OrderedDict[str, object] = OrderedDict()  # per-process cache, like Streamlit's per-session one
_AGES_LOCK = threading.Lock()
MAX_CACHED_AGES = 256


def in_language(language: str):
    """Shared helpers translate with ``i18n.tr``; this sets the language for one response."""
    return i18n.use_language(language)


class LookupUnavailable(RuntimeError):
    """The trusted model required outside CTI-only mode is not ready."""


def _artifact(settings: ApiSettings):
    from ..ml_artifact import load_trusted_ml_artifact

    if settings.cti_only or settings.model_dir is None:
        return None
    try:
        return load_trusted_ml_artifact(Path(settings.model_dir), expected_checksum=settings.model_sha256)
    except (OSError, TypeError, ValueError) as error:
        raise LookupUnavailable(type(error).__name__) from None


def status(settings: ApiSettings, language: str) -> dict:
    """The notices Streamlit shows above the lookup field."""
    from ..cti_cache import list_cti_cache_status

    with in_language(language):
        tr = i18n.tr
        notices: list[dict] = []
        try:
            artifact = _artifact(settings)
        except LookupUnavailable as error:
            return {"ready": False, "notices": [
                {"kind": "error", "text": tr("The local ML artifact is not ready. Set up a trusted artifact to run quick lookup.")},
                {"kind": "caption", "text": str(error)}]}
        if artifact is not None and getattr(artifact.metadata, "evaluation_status", None) == "demo_only_synthetic":
            notices.append({"kind": "warning", "text": tr(
                "Demo ML artifact active. It uses synthetic training data only to exercise the interface and must "
                "not be interpreted as measured model performance.")})
        try:
            empty = not (settings.cti_db_path and list_cti_cache_status(settings.cti_db_path))
        except Exception:  # noqa: BLE001 - a busy or missing cache reads as empty here, as in Streamlit
            empty = True
        if empty:
            notices.append({"kind": "warning", "text": tr(
                "CTI cache is empty. CTI-only lookup has no known-indicator evidence." if settings.cti_only else
                "CTI cache is empty. Quick lookup can still use the ML model, but known-indicator matching is unavailable.")})
        return {
            "ready": True,
            "notices": notices,
            "label": tr("URL, domain or IP"),
            "placeholder": tr("example.com, 143.20.185.213, or https://example.com/path"),
            "button": tr("Check"),
            "caption": tr("Passive by design · no page visit · no DNS resolution · no download"),
            "empty_input": tr("Enter a URL, domain or IP before checking it."),
        }


def _console(result) -> list[dict]:
    """The nodes of ``_render_signal_console`` (same rules, without HTML)."""
    from ..ui_quick_lookup import _presentation_for

    tr = i18n.tr
    visual = _presentation_for(result.verdict.value)
    count = len(result.evidence)
    nodes = [{"tone": "danger" if count else "safe", "label": tr("Local threat intelligence"),
              "value": (tr("{count} CTI match", count=count) if count == 1 else tr("{count} CTI matches", count=count))
              if count else tr("No CTI match"),
              "sub": tr("ThreatFox · URLhaus · SGB cache")}]
    if result.ml_score is not None:
        if result.verdict.value == "known_threat":
            tone, value = "neutral", tr("Context only")
            sub = tr("Model score {score} · final decision from CTI", score=f"{result.ml_score:.4f}")
        elif result.ml_tier == "high":
            tone, value, sub = "danger", tr("High ML tier"), tr("Model score {score}", score=f"{result.ml_score:.4f}")
        elif result.ml_tier in {"medium", "low"}:
            tone, value = "review", tr("{tier} ML tier", tier=tr(result.ml_tier.title()))
            sub = tr("Model score {score}", score=f"{result.ml_score:.4f}")
        else:
            tone, value, sub = "safe", tr("Below threshold"), tr("Model score {score}", score=f"{result.ml_score:.4f}")
        nodes.append({"tone": tone, "label": tr("Host model"), "value": value, "sub": sub})
    lexical = result.lexical_context
    shape = [
        tr("depth {value}", value=lexical.subdomain_depth),
        tr("numeric {value}", value=f"{lexical.numeric_character_ratio:.2f}")
        if lexical.numeric_character_ratio is not None else tr("numeric n/a"),
        tr("entropy {value}", value=f"{lexical.hostname_entropy:.2f}")
        if lexical.hostname_entropy is not None else tr("entropy n/a"),
    ]
    nodes.append({"tone": "info", "label": tr("Host shape context"), "value": result.normalized_domain,
                  "sub": " · ".join(shape)})
    nodes.append({"tone": visual.signal_tone, "label": tr("Decision"), "value": tr(visual.kicker), "sub": tr(visual.title)})
    return nodes


def _ml_card(result) -> dict | None:
    """``_render_ml_risk_card`` values (shown only when a model scored)."""
    from ..ui_quick_lookup import _ml_signal_presentation

    if result.ml_score is None:
        return None
    tr = i18n.tr
    tone, level, subtitle, score, explanation = _ml_signal_presentation(result)
    known = result.verdict.value == "known_threat"
    return {"tone": tone, "level": level, "subtitle": subtitle, "score": score,
            "kicker": tr("ML context") if known else tr("ML risk signal"),
            "scale": None if known else [tr("Minimal"), tr("Low"), tr("Medium"), tr("High")],
            "explanation": explanation,
            "note": tr("Model context · not a verdict or probability") if known
            else tr("Model signal strength · not a probability")}


def _age_block(age) -> dict:
    """``_render_age_result`` values."""
    from ..ui_quick_lookup import _AGE_TONES, _age_text

    tr = i18n.tr
    if age.status == "found" and age.age_days is not None:
        tone, label = _AGE_TONES[age.tier]
        sub = tr("Registered {date}", date=age.registered_at.date().isoformat())
        if age.registrar:
            sub += f" · {age.registrar}"
        value = f"{tr(label)} · {_age_text(age.age_days)}"
    elif age.status == "found":
        tone, value, sub = "info", tr("Registered"), tr("The registry did not publish a registration date.")
    elif age.status == "not_found":
        tone, value = "review", tr("Not in the registry")
        sub = tr("Not registered, or a name on a shared platform the registry does not list.")
    elif age.status == "shared_platform":
        tone, value = "review", tr("Shared platform · {platform}", platform=age.platform)
        sub = tr("Anyone can open a free name on this platform, so it has no registration date of its own. Often used for phishing pages.")
    elif age.status == "unsupported":
        tone, value, sub = "info", tr("No registry data"), tr("This extension has no public RDAP service.")
    else:
        tone, value, sub = "info", tr("Lookup failed"), tr("The registry did not answer. Try again later.")
    return {"tone": tone, "label": f"{tr('Site age')} · {age.domain}", "value": value, "sub": sub,
            "caption": tr("A very new site is a reason to look closer. New is not proof: check before trusting it.")
            if age.tier == "very_new" else None}


def _suffix_rules(settings: ApiSettings):
    from ..popular_domains import load_suffix_rules

    return load_suffix_rules(Path(settings.cti_db_path)) if settings.cti_db_path else frozenset()


def lookup(settings: ApiSettings, language: str, value: str) -> dict:
    """``analyze_quick_lookup_from_cache`` + ``render_quick_lookup_result`` as data."""
    from ..dashboard import format_timestamp
    from ..domain_age import rdap_domain
    from ..quick_lookup import analyze_quick_lookup_from_cache
    from ..ui_quick_lookup import _match_type_label, _presentation_for, _reason_text
    from ..ui_simple_review import lookup_links
    from .behavior import lookup_behavior, scored_rows
    from .review import _owner_lookup

    behavior_rows = None if settings.public_mode else scored_rows(settings)
    with in_language(language):
        tr = i18n.tr
        artifact = _artifact(settings)
        try:
            result = analyze_quick_lookup_from_cache(value, settings.cti_db_path, artifact)
        except (TypeError, ValueError) as error:
            return {"error": tr("Lookup input could not be analyzed: {error}", error=tr(str(error)))}

        visual = _presentation_for(result.verdict.value)
        notices = []
        if result.uses_plain_http:
            notices.append({"kind": "warning", "text": tr(
                "HTTP link detected. This connection is not protected by HTTPS. Transport security alone does not "
                "determine whether a site is malicious.")})
        if result.uses_public_ip_literal:
            notices.append({"kind": "info", "text": tr(
                "Direct public-IP URL detected. ThreatFusion treats this as contextual evidence only; the IP or URL "
                "must match CTI or other stronger signals to be classified as a known threat.")})
        normalized = (tr("normalized IP {value}", value=result.normalized_ip) if result.normalized_ip is not None
                      else tr("normalized domain {value}", value=result.normalized_domain))
        reasons = [_reason_text(reason) for reason in result.reasons]
        if not reasons:
            reasons = [tr("No cached CTI match was found.")]
            if result.ml_score is not None:
                reasons.append(tr("The ML score did not cross a review threshold."))

        registry = None
        if not settings.public_mode and settings.cti_db_path is not None:
            if result.normalized_ip is not None:
                owner_lookup = _owner_lookup(settings.cti_db_path)
                owner = owner_lookup(result.normalized_ip) if owner_lookup else None
                registry = {"kind": "owner", "title": tr("Network owner"),
                            "owner": None if owner is None else {
                                "label": f"{tr('Network owner')} · AS{owner.asn}", "value": owner.label,
                                "sub": tr("Country is where the network is registered, not where the server is. Owners are often hosting or CDN companies.")},
                            "unknown": tr("Owner unknown (private address, or the IP owner table is not downloaded yet).")}
            else:
                domain = rdap_domain(result.normalized_domain, _suffix_rules(settings))
                with _AGES_LOCK:
                    cached = _AGES.get(domain) if domain else None
                registry = {"kind": "age", "title": tr("Site age"), "domain": domain,
                            "unavailable": tr("Site age is not available for this name.") if domain is None else None,
                            "button": tr("Check site age"),
                            "caption": tr("Sends only {domain} to the official domain registry (RDAP). Nothing is sent until you press.", domain=domain) if domain else None,
                            "result": _age_block(cached) if cached is not None else None}
            name = None if result.normalized_ip else result.normalized_domain
            links = lookup_links(name, result.normalized_ip)
            behavior = lookup_behavior(settings, behavior_rows, name, result.normalized_ip)
        else:
            links, behavior = [], None

        if result.evidence:
            if result.verdict.value == "known_threat":
                state = {"tone": "danger", "heading": tr("Known threat intelligence matched"), "copy": tr(
                    "Review the matching source records below. Exact URL/domain/IP evidence is stronger than hostname-only context.")}
            else:
                state = {"tone": "review", "heading": tr("Threat intelligence context found"), "copy": tr(
                    "Context was found in the local CTI cache. Review its scope before deciding how to treat the destination.")}
        else:
            state = {"tone": "safe", "heading": tr("No CTI match found"), "copy": tr(
                "The current local CTI cache contains no matching indicator. This does not guarantee that the destination is safe.")}
        rows = [{"Source": item.source, "Match": _match_type_label(item.match_type), "IOC type": item.ioc_type.upper(),
                 "Indicator": item.indicator_value, "Threat type": item.threat_type or "", "Confidence": item.confidence,
                 "First seen": format_timestamp(item.first_seen.isoformat()) if item.first_seen is not None else "",
                 "Last seen": format_timestamp(item.last_seen.isoformat()) if item.last_seen is not None else "",
                 "Tags": ", ".join(item.tags)} for item in result.evidence]
        columns = list(rows[0]) if rows else []
        lexical = result.lexical_context

        return {
            "notices": notices,
            "banner": {"tone": visual.css_class, "icon": visual.icon, "kicker": tr(visual.kicker),
                       "title": tr(visual.title), "summary": tr(visual.summary),
                       "target": result.normalized_url or result.normalized_domain,
                       "meta": [[tr("Input"), f"{result.input_type} · {normalized}"],
                                [tr("Method"), tr("passive lookup only")],
                                [tr("Network requests"), tr("none")]]},
            "overview_title": tr("Signal overview"),
            "ml_card": _ml_card(result),
            "console": _console(result),
            "console_caption": tr("The diagram shows which local evidence paths contributed context. It does not represent a probability or live website scan."),
            "reasons_title": tr("Why this result?"),
            "reasons": reasons,
            "registry": registry,
            "links_title": tr("Look up elsewhere"),
            "links_caption": tr("Look up on outside sites (opens in a new tab; the name or IP is sent to that site):"),
            "links": [{"name": name, "url": url} for name, url in links],
            "behavior": behavior,
            "evidence_title": tr("Threat intelligence evidence"),
            "evidence_state": state,
            "evidence": {"columns": [i18n._COLUMN_TR.get(c, c) if language == "tr" else c for c in columns],
                         "rows": [[row[c] for c in columns] for row in rows]},
            "technical": {"title": tr("Technical domain details"), "caption": tr(
                "These are descriptive hostname-shape features. They are context, not proof that a domain is malicious."),
                "metrics": [{"label": tr("Labels"), "value": lexical.label_count},
                            {"label": tr("Subdomain depth"), "value": lexical.subdomain_depth},
                            {"label": tr("Numeric ratio"), "value": f"{lexical.numeric_character_ratio:.2f}"
                             if lexical.numeric_character_ratio is not None else "N/A"},
                            {"label": tr("Hostname entropy"), "value": f"{lexical.hostname_entropy:.2f}"
                             if lexical.hostname_entropy is not None else "N/A"}]},
            "footer": tr("Quick lookup is passive: ThreatFusion does not open the URL, resolve the domain, or download "
                         "content. A low-risk result means no current signal was raised by the available local CTI cache "
                         "and model; it is not a guarantee that a destination is safe."),
        }


def domain_age(settings: ApiSettings, language: str, value: str) -> dict:
    """The "Check site age" button: one RDAP request for the registrable domain only."""
    from ..domain_age import lookup_domain_age, rdap_domain

    if settings.public_mode or settings.cti_db_path is None:
        raise LookupUnavailable("registry lookups are off in this mode")
    rules = _suffix_rules(settings)
    domain = rdap_domain(value, rules)
    if domain is None:
        raise ValueError("no registrable domain")
    with _AGES_LOCK:
        cached = _AGES.get(domain)
    if cached is None:
        cached = lookup_domain_age(domain, suffix_rules=rules)
        with _AGES_LOCK:
            _AGES[domain] = cached
            while len(_AGES) > MAX_CACHED_AGES:
                _AGES.popitem(last=False)
    with in_language(language):
        return _age_block(cached)
