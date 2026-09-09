"""Task 9: the PDF kerning carrier.

The claims that need checking are different from the text carrier's:

  * the assembled bytes are a *valid PDF* whichever variant each slot takes, because
    the two variants are the same length and the xref stays correct,
  * two recipients' pages are indistinguishable when rasterised at 150 DPI,
  * extraction survives a normalising re-save, which rewrites the numbers and
    recompresses the streams,
  * and print-scan defeats it, which is recorded rather than hoped away.
"""

from __future__ import annotations

import io

import numpy as np
import pikepdf
import pytest

from pqfw.carrier import get_carrier
from pqfw.carriers.pdf import VARIANT_0, VARIANT_1, iter_page_pixels

SOURCE = (
    "MINISTRY OF SOCIAL JUSTICE AND EMPOWERMENT\n"
    "INTERNAL ASSESSMENT NOTE -- RESTRICTED CIRCULATION\n\n"
    "This note is released to the distribution list at annexe A and to no other "
    "reader. It summarises findings from the quarterly review of tender processes "
    "across the four regional offices, together with the recommendations of the "
    "review committee and a provisional timetable for remedial action. Recipients "
    "are reminded that each copy released under this cover is individually "
    "accountable to the person named on the distribution list and can be traced "
    "back to that person if it appears outside the intended readership.\n\n"
    "The committee recommends that scoring sheets be made a mandatory attachment "
    "at the point of award, that a standing exception report be produced for any "
    "award exceeding the service standard, and that the vendor master be reconciled "
    "against the register of companies annually without fail or further delay.\n"
)


def carrier():
    return get_carrier("pdf-kern")


def rng(seed: int = 0) -> np.random.Generator:
    return np.random.default_rng(seed)


def _assemble(plan, bits) -> bytes:
    return carrier().assemble(
        plan.base_segments, [VARIANT_1 if b else VARIANT_0 for b in bits]
    )


# ---------------------------------------------------------------------------


def test_capacity_and_plan_shape() -> None:
    c = carrier()
    capacity = c.capacity(SOURCE.encode())
    assert capacity > 100, "the sample memo should typeset to plenty of gaps"

    plan = c.plan(SOURCE.encode(), m=40, rng=rng())
    assert plan.m == 40
    assert len(plan.base_segments) == 41
    assert plan.carrier == "pdf-kern"
    assert plan.notes is not None and plan.notes["pages"] >= 1

    with pytest.raises(ValueError):
        c.plan(SOURCE.encode(), m=capacity + 1, rng=rng())


def test_both_variants_are_the_same_length_so_offsets_stay_valid() -> None:
    """The property that lets a PDF go through a byte-splicing carrier at all."""
    assert len(VARIANT_0) == len(VARIANT_1) == 4


def test_every_assembly_is_a_valid_pdf() -> None:
    c = carrier()
    m = 40
    plan = c.plan(SOURCE.encode(), m, rng=rng(1))

    for bits in (
        [0] * m,
        [1] * m,
        (rng(2).random(m) < 0.5).astype(int).tolist(),
    ):
        document = _assemble(plan, bits)
        assert document.startswith(b"%PDF-")
        with pikepdf.open(io.BytesIO(document)) as pdf:
            assert len(pdf.pages) == plan.notes["pages"]
        assert len(document) == len(_assemble(plan, [0] * m)), "length must not vary"


def test_extract_roundtrip() -> None:
    c = carrier()
    m = 60
    plan = c.plan(SOURCE.encode(), m, rng=rng(3))
    bits = (rng(4).random(m) < 0.5).astype(int).tolist()
    assert c.extract(_assemble(plan, bits), plan.locators()) == bits


def test_extract_is_stable_across_bit_vectors() -> None:
    """Slot k must read slot k regardless of the other slots -- the addresses are
    (page, TJ ordinal, element index), which marking never changes."""
    c = carrier()
    m = 50
    plan = c.plan(SOURCE.encode(), m, rng=rng(5))
    for seed in (6, 7, 8):
        bits = (rng(seed).random(m) < 0.5).astype(int).tolist()
        assert c.extract(_assemble(plan, bits), plan.locators()) == bits


def test_visual_equivalence_at_150_dpi() -> None:
    """Rasterise a worst case -- every slot marked -- against a completely unmarked
    copy, and check the claim that is actually being made.

    The claim is *not* pixel-identity. A sub-pixel shift changes antialiasing at glyph
    edges, so around 4% of pixels differ and anyone holding two copies can see which
    slots disagree. That is true of every fingerprinting scheme and is the attack the
    Tardos code exists to survive.

    The claim is that a reader of one copy cannot see the mark. That decomposes into
    two measurable things: no glyph is added, removed or reshaped (total ink is
    unchanged), and nothing moves far enough to notice.
    """
    from reportlab.pdfbase.pdfmetrics import stringWidth

    from pqfw.carriers.pdf import FONT_NAME, FONT_SIZE, KERN_SEPARATION_THOUSANDTHS

    c = carrier()
    m = 60
    plan = c.plan(SOURCE.encode(), m, rng=rng(9))
    pages_zero = list(iter_page_pixels(_assemble(plan, [0] * m), dpi=150))
    pages_one = list(iter_page_pixels(_assemble(plan, [1] * m), dpi=150))
    assert len(pages_zero) == len(pages_one) >= 1

    # 1. the separation between variants is a small fraction of an inter-word space
    separation_pt = KERN_SEPARATION_THOUSANDTHS / 1000.0 * FONT_SIZE
    space_pt = stringWidth(" ", FONT_NAME, FONT_SIZE)
    assert separation_pt / space_pt < 0.05, "a gap must not change by 5% of a space"

    for a, b in zip(pages_zero, pages_one):
        assert a.shape == b.shape
        difference = np.abs(a.astype(np.int16) - b.astype(np.int16))

        # 2. glyphs move; none appear, vanish, or change weight
        ink_zero = float((255 - a[:, :, :3].mean(axis=2)).sum())
        ink_one = float((255 - b[:, :, :3].mean(axis=2)).sum())
        ink_delta = abs(ink_zero - ink_one) / max(ink_zero, 1.0)
        assert ink_delta < 0.0005, f"total ink moved by {ink_delta:.4%}"

        # 3. the difference is confined to glyph edges: a shifted edge, not new marks
        changed = float((difference.max(axis=2) > 8).mean())
        assert changed < 0.08, f"{changed:.2%} of pixels changed -- too much to be edges"


def test_the_accumulated_line_displacement_is_recorded_and_small() -> None:
    """Kerns add up along a line. Both the worst case and the typical case are on the
    record, in points, because centring the variants on zero is what keeps them apart:
    a monotone sum would drift twice as far."""
    plan = carrier().plan(SOURCE.encode(), m=40, rng=rng(10))
    worst = plan.notes["max_line_displacement_pt"]
    typical = plan.notes["expected_line_displacement_pt"]
    assert 0 < typical < worst < 0.8, f"worst {worst:.3f}pt, typical {typical:.3f}pt"
    # under a third of a millimetre at the very worst
    assert worst / 72.0 * 25.4 < 0.3


def test_survives_a_normalising_resave() -> None:
    """pikepdf re-save with object streams and compression: offsets change, the numbers
    are rewritten, the content streams are deflated. Extraction parses, so it holds.

    Ghostscript is the reference tool for this and is not installed in this
    environment; a pikepdf save with compression exercises the same code path in the
    carrier -- reparse rather than byte-search.
    """
    c = carrier()
    m = 50
    plan = c.plan(SOURCE.encode(), m, rng=rng(11))
    bits = (rng(12).random(m) < 0.5).astype(int).tolist()
    document = _assemble(plan, bits)

    out = io.BytesIO()
    with pikepdf.open(io.BytesIO(document)) as pdf:
        pdf.save(out, compress_streams=True, object_stream_mode=pikepdf.ObjectStreamMode.generate)
    resaved = out.getvalue()

    assert VARIANT_1 not in resaved, "the re-save must really have rewritten the bytes"
    assert c.extract(resaved, plan.locators()) == bits


def test_print_scan_defeats_it_and_that_is_documented() -> None:
    """Simulated print-scan: rasterise, then there is no content stream left at all.

    A 0.088 pt inter-word adjustment does not survive 300 DPI paper, ink spread and a
    scanner's resampling -- no analysis of the image recovers it. The honest result is
    that every slot reads as an erasure, which is exactly what a raster with no content
    stream produces. Tracing then declines to identify anybody rather than guessing.
    """
    c = carrier()
    m = 40
    plan = c.plan(SOURCE.encode(), m, rng=rng(13))
    document = _assemble(plan, [1] * m)

    page = next(iter_page_pixels(document, dpi=150))
    raster_only = page.tobytes()  # pixels, no PDF structure

    assert c.extract(raster_only, plan.locators()) == [None] * m


def test_strip_marks_gives_every_recipient_the_same_bytes() -> None:
    c = carrier()
    m = 45
    plan = c.plan(SOURCE.encode(), m, rng=rng(14))
    copies = [
        _assemble(plan, (rng(seed).random(m) < 0.5).astype(int).tolist())
        for seed in (15, 16, 17)
    ]
    assert len({c.strip_marks(doc) for doc in copies}) == 1
    assert len(set(copies)) == 3


def test_locators_are_json_serialisable() -> None:
    import json

    plan = carrier().plan(SOURCE.encode(), m=10, rng=rng(18))
    assert json.loads(json.dumps(plan.locators())) == plan.locators()
