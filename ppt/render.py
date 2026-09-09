"""Render a .pptx to PNGs and a PDF using the installed PowerPoint.

LibreOffice is not present on this machine and the skill's soffice wrapper needs a
POSIX socket, so visual QA goes through PowerPoint's own COM automation instead. That
has an advantage worth keeping: the renders come from the application the judges will
actually open the file in, so font substitution and text fit are exactly what they will
see rather than an approximation.

    python ppt/render.py ppt/deck.pptx ppt/render
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import win32com.client

PP_SAVE_AS_PNG = 18
PP_SAVE_AS_PDF = 32


def render(source: Path, out_dir: Path, width: int = 1600) -> list[Path]:
    source = source.resolve()
    out_dir = out_dir.resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    app = win32com.client.Dispatch("PowerPoint.Application")
    deck = None
    try:
        # WithWindow=False keeps the app off screen; PowerPoint refuses to be fully
        # invisible, so this is as quiet as it gets.
        deck = app.Presentations.Open(str(source), WithWindow=False)
        deck.SaveAs(str(out_dir / "deck.pdf"), PP_SAVE_AS_PDF)
        for index, slide in enumerate(deck.Slides, start=1):
            slide.Export(str(out_dir / f"slide-{index}.png"), "PNG", width)
    finally:
        if deck is not None:
            deck.Close()
        app.Quit()

    return sorted(out_dir.glob("slide-*.png"))


if __name__ == "__main__":
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "ppt/deck.pptx")
    dst = Path(sys.argv[2] if len(sys.argv) > 2 else "ppt/render")
    images = render(src, dst)
    for path in images:
        print(path)
    print(f"\n{len(images)} slides -> {dst}")
