"""Language selection for shared helpers: per context, English by default."""
from __future__ import annotations

import threading

from threatfusion import i18n
from threatfusion.i18n import current_language, tr, use_language


def test_english_by_default_and_turkish_inside_use_language():
    assert current_language() == "en" and tr("Known") == "Known"
    with use_language("tr"):
        assert current_language() == "tr" and tr("Known") == i18n._TR["Known"]
        assert tr("Device {number}", number=3) == i18n._TR["Device {number}"].format(number=3)
    assert current_language() == "en"


def test_unknown_language_falls_back_to_english():
    with use_language("de"):
        assert current_language() == "en"


def test_concurrent_requests_do_not_share_their_language():
    seen = {}
    ready = threading.Barrier(2)

    def worker(language):
        with use_language(language):
            ready.wait(timeout=5)  # both inside their block at the same time
            seen[language] = tr("Known")

    threads = [threading.Thread(target=worker, args=(language,)) for language in ("en", "tr")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert seen == {"en": "Known", "tr": i18n._TR["Known"]}
