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

from .i18n import tr
from .memo import cached
from . import ml_local
from .ml_behavior import WINDOW_SECONDS, BehaviorModel, Connection, build_groups, reasons

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

**How does it learn?** It is trained on this computer: examples of real malware and normal computers from public research recordings (Stratosphere Lab, Czech Technical University; Malware-Traffic-Analysis.net) plus this computer's own first days, taken as normal. It retrains once a day as new days arrive. Nothing about your traffic leaves this computer. The same recipe was tested once on recordings it had never seen; the Model evaluation page shows the results.

**How to use it:** A high score is a reason to look, not proof. Updaters, chat apps and sync tools can look similar. Mark what you recognize; your marks help the next version. This tab does not change What to check."""

GUIDE_TR = """**Bu nedir?** Deneysel bir makine öğrenmesi modeli, cihazlarının her hedefle *nasıl* konuştuğuna bakar; adlara ya da tehdit listelerine değil: bağlantılar ne kadar düzenli tekrarlıyor, her seferinde ne kadar veri gidiyor, ne kadar sürüyor, başarısız oluyor mu, hangi port kullanılıyor, hedefin bir site adı var mı ve bu ad ne kadar rastgele görünüyor. "Eve telefon eden" zararlı yazılımların çoğunun tanınabilir bir ritmi vardır.

**Nasıl öğrenir?** Bu bilgisayarda eğitilir: herkese açık araştırma kayıtlarından (Stratosphere Lab, Çek Teknik Üniversitesi; Malware-Traffic-Analysis.net) gerçek zararlı yazılım ve normal bilgisayar örnekleri ile bu bilgisayarın normal kabul edilen ilk günleri. Yeni günler geldikçe günde bir kez yeniden eğitilir. Trafiğinle ilgili hiçbir şey bu bilgisayardan çıkmaz. Aynı tarif hiç görmediği kayıtlarda bir kez test edildi; sonuçlar Model değerlendirme sayfasında.

**Nasıl kullanılır?** Yüksek puan bakmak için bir sebeptir, kanıt değildir. Güncelleyiciler, sohbet ve eşitleme programları benzer görünebilir. Tanıdıklarını işaretle; işaretlerin bir sonraki sürümün daha iyi öğrenmesine yardım eder. Bu sekme Bakılacaklar listesini değiştirmez."""


def _guide() -> str:
    from .i18n import current_language
    return GUIDE_TR if current_language() == "tr" else GUIDE


def model_path(install_dir: Path) -> Path:
    return install_dir / MODEL_FILE


@cached(max_entries=2)
def _load_model(path: str, modified: float) -> BehaviorModel:
    return BehaviorModel.load(Path(path))


@cached(max_entries=2)
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


@cached(max_entries=2, ttl=REFRESH_SECONDS * 2)
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


@cached(max_entries=2, ttl=REFRESH_SECONDS * 2)
def learn(db_path: str, install_dir: str, cti_db: str | None, bucket: int) -> dict:
    """Store complete days of this computer's groups; train the model when it is due."""
    if not ml_local.PUBLIC_FEATURES.exists():
        return {"available": False, "days": 0}
    install = Path(install_dir)
    days_path = install / ml_local.DAYS_FILE
    local = ml_local.LocalDays.load(days_path)
    try:
        popular = _popular(cti_db) if cti_db else None
        if popular:
            from .popular_domains import is_popular

            def popular_name(name):
                return is_popular(name, popular)
        else:
            def popular_name(name):
                return False
        connections, names = read_collector_records(Path(db_path))
        now = time.time()
        if local.update(connections, names, popular_name):
            local.save(days_path)
        if ml_local.due(install, local, now):
            ml_local.save_model(ml_local.train(ml_local.load_public_features(), local), install / MODEL_FILE)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as error:
        return {"available": True, "days": len(local.days), "error": type(error).__name__}
    return {"available": True, "days": len(local.days)}


def level(score: float, threshold: float) -> str:
    """High: above the model's alarm line; Medium: most trees vote malicious; Low otherwise."""
    return "High" if score >= threshold else "Medium" if score >= 0.5 else "Low"


def scored(state_dir: Path | None, cti_db_path: Path | None = None) -> tuple[BehaviorModel, list[dict]] | None:
    """(model, scored groups) when a local model and collector data exist; None otherwise."""
    if state_dir is None:
        return None
    path = model_path(Path(state_dir).parent)
    database = Path(state_dir) / "collector.sqlite"
    if database.exists():  # keep learning this computer's days on every collector view
        learn(str(database), str(Path(state_dir).parent), str(cti_db_path) if cti_db_path else None,
              int(time.time() // REFRESH_SECONDS))
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


def _percent(value) -> str:
    return "–" if value is None else f"%{round(value * 100)}"


TESTS = (
    ("T1_sme_family_recall", "Malware families caught on a device the model never saw (CTU-SME-11)",
     lambda t: _percent(t.get("sme_family_recall")), "≥ %50"),
    ("T2_mcfp_capture_recall", "Never-seen malware recordings caught (Stratosphere MCFP)",
     lambda t: _percent(t.get("mcfp_capture_recall")), "≥ %50"),
    ("T3_mta_recent_capture_recall", "Recent malware recordings caught, 2025–2026 (Malware-Traffic-Analysis.net)",
     lambda t: _percent(t.get("mta_recent_capture_recall")), "≥ %50"),
    ("T4_benign_flags", "False flags per day on normal computers (MCFP normal / a real laptop)",
     lambda t: f"{t.get('benign', {}).get('mcfp_normal_eval', '–')} / {t.get('benign', {}).get('user_eval', '–')}",
     "≤ 1"),
    ("T5_synthetic_low_jitter", "Simulated call-home beacons caught (up to 20 % timing noise)",
     lambda t: _percent(min((v["recall"] for j, v in t.get("synthetic", {}).items() if float(j) <= 0.2),
                            default=None)), "≥ %70"),
)


def declared_test_rows(tests: dict, checks: dict) -> list[dict]:
    """One row per declared test: what was measured, the result, the limit and whether it passed."""
    return [{tr("Test"): tr(title), tr("Result"): result(tests), tr("Limit"): limit,
             tr("Passed"): "✅" if checks.get(key) else "❌"}
            for key, title, result, limit in TESTS if key in checks]


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
- This computer's first days are taken as normal: if it was already infected then, the model learns that as normal. Threat-list checks are not affected.
- The recipe's normal-traffic test covers a few days of one laptop; your network may differ.
- A group needs at least 4 connections to the same destination within a day; single or rare connections are not scored."""


