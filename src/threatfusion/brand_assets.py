"""Embedded product brand assets used by the Streamlit UI."""

from urllib.parse import quote

# A compact vector mark built for CSS masking. The shield + TF monogram +
# network nodes stay monochrome so the active product theme can tint the logo.
_THREATFUSION_LOGO_SVG = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <g fill="none" stroke="#000" stroke-linecap="round" stroke-linejoin="round">
    <path d="M64 8 108 24v34c0 29-17 50-44 62C37 108 20 87 20 58V24L64 8Z" stroke-width="8"/>
    <path d="M36 39h31M51.5 39v48M72 39h23M72 39v49M72 62h19" stroke-width="8"/>
    <path d="M31 92c-8-13-10-30-4-45M96 31c8 8 13 18 15 29M101 76c-3 11-9 20-18 27" stroke-width="4.5"/>
  </g>
  <g fill="#000">
    <circle cx="29" cy="91" r="5"/>
    <circle cx="96" cy="31" r="5"/>
    <circle cx="101" cy="76" r="5"/>
  </g>
</svg>
""".strip()

THREATFUSION_LOGO_DATA_URI = (
    "data:image/svg+xml;charset=UTF-8,"
    + quote(_THREATFUSION_LOGO_SVG, safe="")
)
