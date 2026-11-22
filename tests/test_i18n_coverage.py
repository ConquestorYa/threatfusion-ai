"""Every literal UI string passed to tr() has a Turkish translation."""
import re
from pathlib import Path

from threatfusion.i18n import _TR

ROOT = Path(__file__).resolve().parents[1]
LITERAL = re.compile(r"""\b(?:tr|t)\(\s*(["'])((?:(?!\1).)+)\1\s*[,)]""")


def test_literal_ui_strings_have_turkish_translations():
    files = [*sorted((ROOT / "src/threatfusion").glob("ui_*.py")), *sorted((ROOT / "src/threatfusion/api").glob("*.py"))]
    missing = sorted({(f.name, m.group(2)) for f in files
                      for m in LITERAL.finditer(f.read_text(encoding="utf-8")) if m.group(2) not in _TR})
    assert not missing
