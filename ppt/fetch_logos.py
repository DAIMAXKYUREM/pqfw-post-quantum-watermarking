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

from PIL import Image
from reportlab.graphics import renderPM
from svglib.svglib import svg2rlg

OUT = Path(__file__).resolve().parent / "logos"
CDN = "https://cdn.jsdelivr.net/npm/simple-icons@13/icons/{slug}.svg"

# slug -> (filename, colour). Colour is applied to the path fill so the row reads as one
# system; the marks stay recognisable by shape, which is how logos actually work at this
# size.
# The SVG is filled black and the tint is applied afterwards. Filling it navy
# instead would leave a solid pixel at luminance 54, so inverting that into alpha
# would cap every mark at 79% opacity and print the whole row washed out.
BLACK = "#000000"
NAVY_RGB = (0x1F, 0x38, 0x64)
LOGOS = {
    "python": ("python", BLACK),
    "fastapi": ("fastapi", BLACK),
    "numpy": ("numpy", BLACK),
    "docker": ("docker", BLACK),
    "linux": ("linux", BLACK),
    "github": ("github", BLACK),
    "render": ("render", BLACK),
    "huggingface": ("huggingface", BLACK),
    "gnubash": ("bash", BLACK),
    "pytest": ("pytest", BLACK),
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


def flatten(source: Path, target: Path) -> None:
    """Turn the white-matted render into transparent navy.

    renderPM has no alpha channel, so an opaque white square shipped behind every
    mark. That is invisible on white and a row of faint tiles on the pale card the
    logos actually sit on. Inverting luminance into alpha drops the matte and keeps
    the antialiasing a colour-key would have thrown away.
    """
    grey = Image.open(source).convert("L")
    out = Image.new("RGBA", grey.size, NAVY_RGB + (0,))
    out.putalpha(Image.eval(grey, lambda v: 255 - v))
    out.save(target)


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
        scratch = OUT / "_matte.png"
        renderPM.drawToFile(drawing, str(scratch), fmt="PNG", bg=0xFFFFFF)
        flatten(scratch, path)
        scratch.unlink(missing_ok=True)
        made.append(path)
        print(f"  {name}.png")
    print(f"\n{len(made)} logos -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
