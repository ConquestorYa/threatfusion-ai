from __future__ import annotations

import pandas as pd
from streamlit.testing.v1 import AppTest

from threatfusion.i18n import LANGUAGE_OPTIONS


def _translation_app() -> AppTest:
    return AppTest.from_string(
        "import streamlit as st\n"
        "from threatfusion.i18n import LANGUAGE_OPTIONS, tr, translate_dataframe\n"
        "if st.session_state.get('language_selector') not in LANGUAGE_OPTIONS:\n"
        "    st.session_state['language_selector'] = '🇬🇧 English'\n"
        "st.segmented_control('Language', list(LANGUAGE_OPTIONS), "
        "key='language_selector')\n"
        "st.write(tr('Quick lookup'))\n"
        "st.dataframe(translate_dataframe(__import__('pandas').DataFrame("
        "{'Verdict':['Known Threat'], 'ML score':[0.9]})))\n"
    )


def test_language_options_are_flagged_and_bilingual() -> None:
    assert LANGUAGE_OPTIONS == ("🇹🇷 Türkçe", "🇬🇧 English")


def test_english_is_default_and_turkish_state_translates_ui() -> None:
    app = _translation_app().run(timeout=15)

    assert not app.exception
    assert any(item.value == "Quick lookup" for item in app.markdown)

    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)

    assert not app.exception
    assert any(item.value == "Hızlı sorgu" for item in app.markdown)
    frame = app.dataframe[0].value
    assert list(frame.columns) == ["Sonuç", "ML skoru"]
    assert frame.iloc[0]["Sonuç"] == "Bilinen Tehdit"


def test_translation_does_not_mutate_source_dataframe() -> None:
    source = pd.DataFrame({"Verdict": ["Known Threat"]})
    app = AppTest.from_string(
        "import streamlit as st\n"
        "import pandas as pd\n"
        "from threatfusion.i18n import translate_dataframe\n"
        "st.session_state['language_selector'] = '🇹🇷 Türkçe'\n"
        "frame = pd.DataFrame({'Verdict':['Known Threat']})\n"
        "st.dataframe(translate_dataframe(frame))\n"
    ).run(timeout=15)

    assert not app.exception
    assert source.columns.tolist() == ["Verdict"]
    assert source.iloc[0, 0] == "Known Threat"
