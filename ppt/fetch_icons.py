"""Fetch the pictograms the flow diagrams use, in the two colours the deck needs.

The flow boxes were generic rounded rectangles distinguished only by their captions,
which is the thing that makes a diagram read as filler: four identical boxes in a row
tell the eye nothing before it starts reading. Each stage here gets a mark that says
what it is -- a document, a key, a sealed package, a fingerprint, a ledger, a shield --
so the shape carries meaning at a glance and the caption confirms it.

Bootstrap Icons rather than an emoji font: emoji render in their own colours and at
their own weights, and the two would fight the palette. These are single-path glyphs
that can be recoloured to the exact deck navy or to white for the dark nodes.

Transparency matters here in a way it did not for the logo row. These sit on navy,
orange and green fills, so a white matte would show as a square halo behind every mark.
renderPM cannot write an alpha channel, so each icon is rendered black-on-white and the
luminance is inverted into the alpha channel -- which also keeps the antialiasing that
a colour-key would throw away.

    python ppt/fetch_icons.py
"""

from __future__ import annotations

import io
import re
import urllib.request
from pathlib import Path

from PIL import Image
from reportlab.graphics import renderPM
from svglib.svglib import svg2rlg

OUT = Path(__file__).resolve().parent / "icons"
CDN = "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/icons/{slug}.svg"
SIZE = 256

NAVY = (0x1F, 0x38, 0x64)
WHITE = (0xFF, 0xFF, 0xFF)

# name in the deck -> Bootstrap Icons slug
ICONS = {
    # slide 2 -- the mechanism
    "document": "file-earmark-text-fill",
    "twocopies": "layers-fill",
    "ciphertext": "file-earmark-lock2-fill",
    "keys": "key-fill",
    # slide 3 -- distribute
    "lock": "lock-fill",
    "package": "box-seam-fill",
    # slide 3 -- decrypt and record
    "unlock": "unlock-fill",
    "fingerprint": "fingerprint",
    "receipt": "patch-check-fill",
    "ledger": "hdd-stack-fill",
    # slide 3 -- trace
    "leak": "file-earmark-break-fill",
    "score": "bar-chart-fill",
    "lookup": "search",
    "verdict": "shield-fill-check",
    # supporting
    "offline": "wifi-off",
    "test": "clipboard2-check-fill",
    "people": "people-fill",
    "clock": "stopwatch-fill",
}


def fetch(slug: str) -> str:
    with urllib.request.urlopen(CDN.format(slug=slug), timeout=60) as response:
        return response.read().decode("utf-8")


def blacken(svg: str) -> str:
    """Bootstrap glyphs inherit currentColor; pin them to black for the alpha pass."""
    svg = re.sub(r'\sfill="currentColor"', ' fill="#000000"', svg)
    svg = re.sub(r'\sstroke="currentColor"', ' stroke="#000000"', svg)
    return svg


def tint(source: Path, target: Path, colour: tuple[int, int, int]) -> None:
    grey = Image.open(source).convert("L")
    alpha = Image.eval(grey, lambda v: 255 - v)
    out = Image.new("RGBA", grey.size, colour + (0,))
    out.putalpha(alpha)
    out.save(target)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    scratch = OUT / "_mono.png"
    made = 0
    for name, slug in ICONS.items():
        try:
            svg = blacken(fetch(slug))
        except Exception as exc:  # a missing slug must not stop the rest
            print(f"  SKIP {name} ({slug}): {exc}")
            continue
        drawing = svg2rlg(io.BytesIO(svg.encode("utf-8")))
        if drawing is None:
            print(f"  SKIP {name} ({slug}): could not parse")
            continue
        scale = SIZE / max(drawing.width or 16, drawing.height or 16)
        drawing.width *= scale
        drawing.height *= scale
        drawing.scale(scale, scale)
        renderPM.drawToFile(drawing, str(scratch), fmt="PNG", bg=0xFFFFFF)
        tint(scratch, OUT / f"{name}.png", WHITE)
        tint(scratch, OUT / f"{name}-navy.png", NAVY)
        made += 1
        print(f"  {name}  <- {slug}")
    scratch.unlink(missing_ok=True)
    print(f"\n{made}/{len(ICONS)} icons -> {OUT}")
    return 0 if made == len(ICONS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
