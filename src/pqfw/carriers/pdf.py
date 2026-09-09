"""PDF kerning carrier.

A slot is one inter-word kern inside a text-showing operator:

    variant_0 = b"+4.0"     tighten the gap by 4/1000 em
    variant_1 = b"-4.0"     loosen  the gap by 4/1000 em

In a ``TJ`` array a number is subtracted from the horizontal coordinate in thousandths
of an em, so the two variants differ by 8/1000 em -- the separation the design calls
for. At 11 pt that is 0.088 pt between them, about a fifth of a pixel at 150 DPI, and
2.9% of the width of a space.

Why the pair is centred on zero rather than being (0, -8)
---------------------------------------------------------
Kerns accumulate along a line. With variants of 0 and -8, a line whose slots all
happen to be marked drifts monotonically: at fourteen gaps per line the last word sits
1.2 pt (2.6 px at 150 DPI) right of where the unmarked copy puts it. Splitting the
same 8/1000 separation symmetrically about zero makes the drift a mean-zero random
walk instead of a sum, so it grows as sqrt(gaps) rather than linearly and the
worst case halves. The quantity that carries the bit is unchanged.

Why the two variants are the same number of bytes
-------------------------------------------------
``+4.0`` and ``-4.0`` are both four bytes; PDF permits a leading ``+`` on a number, so
the positive variant can be written to match the negative one. That matters more than
it looks: the carrier contract is that a document is
``base[0] + slot[0] + base[1] + ...``, and a PDF has a cross-reference table of byte
offsets and a ``/Length`` on every stream. Equal-length variants mean every offset and
every length stays correct no matter which variant is chosen, so the assembled bytes
are a valid PDF without anything being recomputed after the fact -- and the crypto
layer never needs to know it is handling a PDF at all.

Extraction does not depend on byte offsets. It parses the content stream with pikepdf
and reads the number at a recorded (page, TJ ordinal, element index), so a copy that
has been through a normalising re-save -- which rewrites ``-4.0`` as ``-4`` and
recompresses the stream -- is still readable.

What "visually identical" does and does not mean
------------------------------------------------
It means a reader of a *single* copy cannot see the mark: each inter-word gap moves by
2.9% of a space width, against the 10-50% variation ordinary justification introduces,
and the total ink on the page is identical to within 0.01%. No glyph is added, removed
or reshaped -- they are only positioned.

It does **not** mean two copies are pixel-identical. Diff two rasterised copies and
about 4% of pixels differ, at glyph edges, because a sub-pixel shift changes
antialiasing. Anyone holding two copies can therefore see *which* slots disagree
between them. That is true of every fingerprinting scheme ever built, and it is
precisely the attack the Tardos code is designed to survive: knowing where the copies
differ does not tell a coalition what to put there, because at each such slot they hold
one variant key each and cannot produce a third answer.

Scope
-----
Sender-generated documents only. PQFW types the document, so it controls the
typesetting. Retrofitting slots into an arbitrary uploaded PDF is a different and much
harder problem -- content streams in the wild are compressed, subset-encoded, produced
by a hundred different generators, and frequently do not have inter-word gaps as
separate operands at all -- and this prototype does not attempt it.

Base-14 Helvetica with WinAnsi encoding, so text outside Latin-1 is replaced rather
than rendered. The text carrier handles full Unicode; this one does not.
"""

from __future__ import annotations

import io
from typing import Any, Iterator, Sequence

import numpy as np
import pikepdf
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas

from pqfw.carrier import CarrierPlan, Slot, assemble_interleaved, register

PLACEHOLDER = b"+0.0"
"""What every inter-word gap is rendered with. Gaps that are not slots keep it, which
is why it is neutral; slots have it replaced by one of the two variants."""

VARIANT_0 = b"+4.0"
VARIANT_1 = b"-4.0"
KERN_SEPARATION_THOUSANDTHS = 8.0
"""Difference between the two variants, in thousandths of an em."""

FONT_NAME = "Helvetica"
FONT_SIZE = 11.0
LEADING = 15.0
MARGIN = 56.0
# Kerns still accumulate along a line, just symmetrically. Reserving the worst case in
# the right margin keeps a line whose slots all fall the same way inside the text block.
RIGHT_SLACK = 4.0


def _pdf_escape(word: str) -> str:
    return word.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _to_winansi(text: str) -> str:
    return text.encode("cp1252", errors="replace").decode("cp1252")


class PdfKernCarrier:
    name = "pdf-kern"

    # -- layout --------------------------------------------------------------

    def _layout(self, source: bytes) -> list[list[list[str]]]:
        """Word-wrap into pages of lines of words. Deterministic: no randomness."""
        text = _to_winansi(source.decode("utf-8", errors="replace"))
        width, height = A4
        max_width = width - 2 * MARGIN - RIGHT_SLACK
        rows_per_page = max(1, int((height - 2 * MARGIN) // LEADING))

        lines: list[list[str]] = []
        for paragraph in text.split("\n"):
            words = paragraph.split()
            if not words:
                lines.append([])
                continue
            current: list[str] = []
            for word in words:
                candidate = current + [word]
                if (
                    current
                    and stringWidth(" ".join(candidate), FONT_NAME, FONT_SIZE) > max_width
                ):
                    lines.append(current)
                    current = [word]
                else:
                    current = candidate
            lines.append(current)

        pages: list[list[list[str]]] = []
        for start in range(0, len(lines), rows_per_page):
            pages.append(lines[start : start + rows_per_page])
        return pages or [[[]]]

    def _gap_map(self, pages: list[list[list[str]]]) -> list[dict[str, Any]]:
        """Every inter-word gap, in the order the content streams emit them.

        Gap g of a line sits at element index 2g+1 of that line's TJ array:
        ``[(word ) kern (word ) kern (word )]``.
        """
        out: list[dict[str, Any]] = []
        for page_index, lines in enumerate(pages):
            tj_ordinal = 0
            for words in lines:
                if len(words) < 2:
                    if words:
                        tj_ordinal += 1
                    continue
                for gap in range(len(words) - 1):
                    out.append(
                        {
                            "carrier": self.name,
                            "page": page_index,
                            "tj_ordinal": tj_ordinal,
                            "element_index": 2 * gap + 1,
                        }
                    )
                tj_ordinal += 1
        return out

    def capacity(self, source: bytes) -> int:
        return len(self._gap_map(self._layout(source)))

    # -- rendering -----------------------------------------------------------

    def _render(self, pages: list[list[list[str]]]) -> bytes:
        """Emit the PDF with a zero kern at every gap.

        ``pageCompression=0`` is load-bearing, not a debugging convenience: the slot
        bytes have to appear literally in the file for the carrier's split-and-reassemble
        contract to work.
        """
        buf = io.BytesIO()
        width, height = A4
        pdf = canvas.Canvas(buf, pagesize=A4, pageCompression=0, invariant=1)
        pdf.setTitle("PQFW protected document")

        for lines in pages:
            y = height - MARGIN
            text = pdf.beginText(MARGIN, y)
            text.setFont(FONT_NAME, FONT_SIZE)
            text.setLeading(LEADING)
            for words in lines:
                if not words:
                    text.textLine("")
                    continue
                pieces: list[str] = []
                for index, word in enumerate(words):
                    trailing = " " if index < len(words) - 1 else ""
                    pieces.append(f"({_pdf_escape(word)}{trailing})")
                    if trailing:
                        pieces.append(PLACEHOLDER.decode("ascii"))
                # One raw TJ per line, and no other text-showing operator anywhere, so
                # "the j-th TJ on this page" is a stable address for a slot.
                text._code.append("[" + " ".join(pieces) + "] TJ")
                text._code.append("T*")
            pdf.drawText(text)
            pdf.showPage()

        pdf.save()
        return buf.getvalue()

    # -- carrier protocol ----------------------------------------------------

    def plan(self, source: bytes, m: int, rng: np.random.Generator) -> CarrierPlan:
        pages = self._layout(source)
        gaps = self._gap_map(pages)
        if m < 1:
            raise ValueError("a plan needs at least one slot")
        if m > len(gaps):
            raise ValueError(
                f"this document typesets to {len(gaps)} inter-word gaps, cannot place "
                f"{m} slots; shorten the code or lengthen the document"
            )

        rendered = self._render(pages)
        positions = _find_all(rendered, PLACEHOLDER)
        if len(positions) != len(gaps):
            raise RuntimeError(
                f"expected {len(gaps)} kern tokens in the rendered PDF, found "
                f"{len(positions)}: the renderer emitted something unexpected and the "
                f"slot addresses cannot be trusted"
            )

        # One slot per evenly sized bucket, at a random offset inside it: an even
        # spread degrades gracefully under page loss, the random offset keeps the slot
        # positions from being derivable from the document alone.
        chosen: list[int] = []
        for i in range(m):
            lo = (i * len(gaps)) // m
            hi = max(((i + 1) * len(gaps)) // m, lo + 1)
            chosen.append(int(rng.integers(lo, hi)))

        base_segments: list[bytes] = []
        slots: list[Slot] = []
        cursor = 0
        for index, gap_ordinal in enumerate(chosen):
            at = positions[gap_ordinal]
            base_segments.append(rendered[cursor:at])
            slots.append(
                Slot(
                    index=index,
                    variant_0=VARIANT_0,
                    variant_1=VARIANT_1,
                    locator=gaps[gap_ordinal],
                )
            )
            cursor = at + len(PLACEHOLDER)
        base_segments.append(rendered[cursor:])

        return CarrierPlan(
            base_segments=base_segments,
            slots=slots,
            carrier=self.name,
            notes={
                "pages": len(pages),
                "usable_gaps": len(gaps),
                "rendered_bytes": len(rendered),
                "font": f"{FONT_NAME} {FONT_SIZE}pt",
                "kern_separation_thousandths_em": KERN_SEPARATION_THOUSANDTHS,
                "max_line_displacement_pt": _max_line_shift(pages),
                "expected_line_displacement_pt": _expected_line_shift(pages),
            },
        )

    def assemble(self, base_segments: Sequence[bytes], chosen: Sequence[bytes]) -> bytes:
        return assemble_interleaved(base_segments, chosen)

    def extract(self, leaked: bytes, locators: Sequence[dict[str, Any]]) -> list[int | None]:
        """Read each slot's kern by parsing the content stream.

        Deliberately not a byte search: a copy that has been through a normalising
        re-save has different offsets, different stream compression, and ``-8`` where we
        wrote ``-8.0``. Parsing sees through all of that.
        """
        try:
            arrays = _tj_arrays(leaked)
        except Exception:
            return [None] * len(locators)

        out: list[int | None] = []
        for loc in locators:
            key = (int(loc["page"]), int(loc["tj_ordinal"]))
            element = int(loc["element_index"])
            array = arrays.get(key)
            if array is None or element >= len(array):
                out.append(None)
                continue
            value = array[element]
            if value is None:
                out.append(None)
                continue
            # The variants straddle zero, so zero is the decision boundary and a
            # re-save that rewrites -4.0 as -4 still lands on the right side.
            out.append(1 if value < 0.0 else 0)
        return out

    def strip_marks(self, document: bytes) -> bytes:
        """Turn every marked kern back into a zero one.

        Byte-length preserving, which is what lets two recipients' copies be compared
        for exact equality in the visual-equivalence test.
        """
        return document.replace(VARIANT_1, VARIANT_0)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _find_all(haystack: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        at = haystack.find(needle, start)
        if at < 0:
            return out
        out.append(at)
        start = at + len(needle)


def _tj_arrays(document: bytes) -> dict[tuple[int, int], list[float | None]]:
    """(page, TJ ordinal) -> the array's elements, numbers as floats and strings as None."""
    out: dict[tuple[int, int], list[float | None]] = {}
    with pikepdf.open(io.BytesIO(document)) as pdf:
        for page_index, page in enumerate(pdf.pages):
            ordinal = 0
            for instruction in pikepdf.parse_content_stream(page):
                if str(instruction.operator) != "TJ":
                    continue
                elements: list[float | None] = []
                for operand in instruction.operands[0]:
                    try:
                        elements.append(float(operand))
                    except (TypeError, ValueError):
                        elements.append(None)
                out[(page_index, ordinal)] = elements
                ordinal += 1
    return out


def _line_gap_counts(pages: list[list[list[str]]]) -> list[int]:
    return [len(words) - 1 for lines in pages for words in lines if len(words) > 1]


def _max_line_shift(pages: list[list[list[str]]]) -> float:
    """Worst-case accumulated displacement at the end of a line, in points.

    Every gap moves by half the separation in one direction or the other, so the worst
    case is all of them falling the same way. Reported in the plan notes so the number
    is on the record rather than assumed to be small.
    """
    most_gaps = max(_line_gap_counts(pages), default=0)
    return most_gaps * (KERN_SEPARATION_THOUSANDTHS / 2.0) / 1000.0 * FONT_SIZE


def _expected_line_shift(pages: list[list[list[str]]]) -> float:
    """Typical accumulated displacement: a mean-zero random walk, so sqrt(gaps)."""
    counts = _line_gap_counts(pages)
    if not counts:
        return 0.0
    return (max(counts) ** 0.5) * (KERN_SEPARATION_THOUSANDTHS / 2.0) / 1000.0 * FONT_SIZE


def render_unmarked(source: bytes) -> bytes:
    """The document as it would look with every slot at variant 0. Demo convenience."""
    carrier = CARRIER
    pages = carrier._layout(source)
    return carrier._render(pages)


def iter_page_pixels(document: bytes, dpi: int = 150) -> Iterator[Any]:
    """Rasterise, for the visual-equivalence test. Requires the dev extra."""
    import pypdfium2 as pdfium

    pdf = pdfium.PdfDocument(io.BytesIO(document))
    try:
        for index in range(len(pdf)):
            yield pdf[index].render(scale=dpi / 72.0).to_numpy()
    finally:
        pdf.close()


CARRIER = PdfKernCarrier()
register(CARRIER)
