"""Fetch tech-stack marks and rasterise them for the deck.

simple-icons ships single-path monochrome SVGs, so each one can be recoloured to the
deck palette before rendering rather than dropped in as a stock brand colour -- a row of
logos in eight different brand colours is exactly the ransom-note look worth avoiding.

    python ppt/fetch_logos.py
"""

from __future__ import annotations

import io
import re
import urllib.request
from pathlib import Path

from reportlab.graphics import renderPM
from svglib.svglib import svg2rlg

OUT = Path(__file__).resolve().parent / "logos"
CDN = "https://cdn.jsdelivr.net/npm/simple-icons@13/icons/{slug}.svg"

# slug -> (filename, colour). Colour is applied to the path fill so the row reads as one
# system; the marks stay recognisable by shape, which is how logos actually work at this
# size.
NAVY = "#1F3864"
LOGOS = {
    "python": ("python", NAVY),
    "fastapi": ("fastapi", NAVY),
    "numpy": ("numpy", NAVY),
    "docker": ("docker", NAVY),
    "linux": ("linux", NAVY),
    "github": ("github", NAVY),
    "render": ("render", NAVY),
    "huggingface": ("huggingface", NAVY),
    "gnubash": ("bash", NAVY),
    "pytest": ("pytest", NAVY),
}


def fetch(slug: str) -> str:
    with urllib.request.urlopen(CDN.format(slug=slug), timeout=60) as response:
        return response.read().decode("utf-8")


def recolour(svg: str, colour: str) -> str:
    """simple-icons paths inherit currentColor; give them an explicit fill."""
    svg = re.sub(r'\sfill="[^"]*"', "", svg)
    if "<path" in svg:
        svg = svg.replace("<path", f'<path fill="{colour}"', 1)
    return svg


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    made = []
    for slug, (name, colour) in LOGOS.items():
        try:
            svg = recolour(fetch(slug), colour)
        except Exception as exc:  # a missing icon must not stop the rest
            print(f"  skip {slug}: {exc}")
            continue
        drawing = svg2rlg(io.BytesIO(svg.encode("utf-8")))
        if drawing is None:
            print(f"  skip {slug}: could not parse")
            continue
        # simple-icons are 24x24; scale up so the raster is crisp on a projector
        scale = 256 / max(drawing.width or 24, drawing.height or 24)
        drawing.width *= scale
        drawing.height *= scale
        drawing.scale(scale, scale)
        path = OUT / f"{name}.png"
        renderPM.drawToFile(drawing, str(path), fmt="PNG", bg=0xFFFFFF)
        made.append(path)
        print(f"  {name}.png")
    print(f"\n{len(made)} logos -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
