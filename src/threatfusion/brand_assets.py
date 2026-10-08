"""Embedded product brand assets used by the Streamlit UI."""

from urllib.parse import quote

# A compact monochrome mark used as a CSS mask so the active theme tints it:
# two overlapping rings (threat intelligence and local telemetry) with the
# filled overlap where evidence from both meets.
_THREATFUSION_LOGO_SVG = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <defs><clipPath id="a"><circle cx="46" cy="64" r="34"/></clipPath></defs>
  <g fill="none" stroke="#000" stroke-width="8">
    <circle cx="46" cy="64" r="34"/>
    <circle cx="82" cy="64" r="34"/>
  </g>
  <circle cx="82" cy="64" r="34" fill="#000" clip-path="url(#a)"/>
</svg>
""".strip()

THREATFUSION_LOGO_DATA_URI = (
    "data:image/svg+xml;charset=UTF-8,"
    + quote(_THREATFUSION_LOGO_SVG, safe="")
)
