"""Zero-width-space text carrier.

A slot is one inter-word space. The two variants are:

    variant_0 = b" "                 (U+0020)
    variant_1 = b" \\xe2\\x80\\x8b"     (U+0020 followed by U+200B ZERO WIDTH SPACE)

Both render identically in a browser, in a terminal, in Word, and on paper.

How a slot is addressed
-----------------------
Two ways, and the locator carries both.

The **anchor** is the real address: a digest of the normalised text that runs up to the
slot. It is what the slot sits *after*, not where the slot sits, so an edit somewhere
else in the document does not move it. This replaces addressing by ordinal alone, which
was the sharpest weakness the evaluation harness found: a locator that says "the k-th
space in the document" is shifted by a single word inserted or deleted anywhere ahead
of it, and the extractor then reads the neighbouring slots instead. Two of the four
attacks that defeated this carrier -- ``insert_word_start`` and ``delete_word_start`` --
were nothing more than that, and neither of them touched a single mark.

The **ordinal** is kept for two jobs. Repeated boilerplate yields repeated anchors, and
the ordinal picks the intended one out of the candidates. And a package sealed before
anchoring existed carries an ordinal and nothing else, so ``extract`` must still be able
to read one.

Anchors are computed over the document with marks stripped, on both sides. That matters:
the planner sees an unmarked document and the tracer sees a marked one, and the two have
to agree. Stripping also means a slot's own mark cannot perturb its neighbours' anchors.
Since U+200B has no 0x20 byte in UTF-8, stripping never changes how many spaces there
are or what order they come in -- only their byte offsets -- so the k-th space of the
stripped copy is the k-th space of the leaked copy, and a position found in one can be
read in the other.

When an anchor cannot be found, the slot reads as ``None``. That is deliberate and it is
the same choice the rest of the system makes: an erasure drops out of the Tardos sum,
while a guess that happens to be wrong actively pushes the true leaker's score down. The
failure mode stays "we could not read this", never "we read it and it said someone else".

Why the ordinal is the count of U+0020 characters
-------------------------------------------------
Marking a slot appends a zero-width space *after* the U+0020; it neither adds nor removes
a U+0020. So the ordinal of every other slot is unchanged by marking, and extraction on a
marked copy enumerates exactly the same positions the planner did. Truncation removes a
suffix of the ordinals, which is why a cut document yields None for its tail rather than
garbage for the whole thing.

In UTF-8, byte 0x20 only ever occurs as the space character -- continuation bytes are
all >= 0x80 -- so this counting can be done on raw bytes without decoding, and survives
a document that is not valid UTF-8 at all.

Threat model (honest version, and it belongs in the README too)
---------------------------------------------------------------
This carrier survives: redistribution of the file itself, copying into anything that
preserves the byte stream, email attachment, archive/compress round-trips, and -- since
anchoring -- a word inserted or deleted elsewhere in the document.

This carrier does NOT survive: pasting through an editor that normalises whitespace,
retyping, OCR of a scan, or any "strip invisible characters" tool. Those attacks delete
the marks themselves, and no addressing scheme can recover a mark that is gone. They are
real, the evaluation harness measures every one of them, and defeating them needs a
carrier that lives in the words rather than between them. The declared threat model is
redistribution of the artefact, not manual reconstruction of its content.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any, Sequence

import numpy as np

from pqfw.carrier import CarrierPlan, Slot, assemble_interleaved, register

SPACE = b" "
ZWSP = "​".encode("utf-8")  # b"\xe2\x80\x8b"

VARIANT_0 = SPACE
VARIANT_1 = SPACE + ZWSP

# Anchor geometry. The window is measured in normalised characters rather than raw
# bytes so that punctuation and whitespace fiddling do not change how much text it
# covers; ANCHOR_RAW is just a generous slice to normalise down from.
ANCHOR_RAW = 240
ANCHOR_CHARS = 40
ANCHOR_HEX = 12

# How far an *ambiguous* anchor is allowed to have moved before the match is refused.
# A unique anchor needs no such bound -- it is proof, and the slot can have moved as far
# as it likes. Repeated text is different: the tie-break is inference, and inference
# without a bound will happily resolve a truncated-away slot to the same passage
# occurring earlier in the document, which reads a real bit belonging to a different
# slot. 48 word boundaries is a few sentences: comfortably more than any edit worth
# surviving, comfortably less than a jump to another repetition of a passage long
# enough to collide.
AMBIGUOUS_DRIFT = 48

# Named so a running deployment can report which addressing scheme it is built with;
# see /api/health. A marker that is derived rather than typed out cannot go stale.
ADDRESSING = "content-anchored"

_NOISE = re.compile(rb"[^a-z0-9]+")


def _space_positions(document: bytes) -> list[int]:
    """Byte offsets of every U+0020 in the document, in order."""
    out: list[int] = []
    start = 0
    while True:
        i = document.find(0x20, start)
        if i < 0:
            return out
        out.append(i)
        start = i + 1


def _normalise_window(raw: bytes) -> bytes:
    """Case, punctuation and whitespace folded away.

    An anchor has to survive the document being reflowed or re-punctuated without
    surviving the document being rewritten, so everything that is not a letter or a
    digit collapses to a single space.
    """
    return _NOISE.sub(b" ", raw.lower()).strip()


def _anchor_at(text: bytes, pos: int) -> str:
    """Digest of the normalised text immediately preceding ``pos``.

    Preceding rather than surrounding: the point is to be unmoved by an edit ahead of
    the slot, and a window that reached forwards would also have to survive a truncated
    document, which it cannot.
    """
    window = _normalise_window(text[max(0, pos - ANCHOR_RAW) : pos])[-ANCHOR_CHARS:]
    return hashlib.sha3_256(window).hexdigest()[:ANCHOR_HEX]


class TextZwspCarrier:
    name = "text-zwsp"

    def capacity(self, source: bytes) -> int:
        return len(_space_positions(self.normalise(source)))

    def normalise(self, source: bytes) -> bytes:
        """Remove any pre-existing zero-width spaces.

        A source that already contains ZWSPs would read as marked before anyone marked
        it, so the planner strips them and records that it did. Stripping is safe: a
        ZWSP carries no visible content by construction.
        """
        return source.replace(ZWSP, b"")

    def plan(self, source: bytes, m: int, rng: np.random.Generator) -> CarrierPlan:
        normalised = self.normalise(source)
        positions = _space_positions(normalised)
        available = len(positions)
        if m < 1:
            raise ValueError("a plan needs at least one slot")
        if m > available:
            raise ValueError(
                f"document holds {available} usable word boundaries, cannot place {m} "
                f"slots; shorten the code or lengthen the document"
            )

        # One slot per evenly sized bucket, at a random offset inside the bucket. The
        # even spread means truncation degrades the code smoothly instead of removing
        # a cluster; the random offset inside the bucket means the slot positions are
        # not derivable from the document alone.
        chosen: list[int] = []
        for i in range(m):
            lo = (i * available) // m
            hi = ((i + 1) * available) // m
            hi = max(hi, lo + 1)
            chosen.append(positions[int(rng.integers(lo, hi))])

        base_segments: list[bytes] = []
        slots: list[Slot] = []
        cursor = 0
        for index, pos in enumerate(chosen):
            base_segments.append(normalised[cursor:pos])
            ordinal = _ordinal_of(positions, pos)
            slots.append(
                Slot(
                    index=index,
                    variant_0=VARIANT_0,
                    variant_1=VARIANT_1,
                    locator={
                        "carrier": self.name,
                        "word_boundary_ordinal": ordinal,
                        "anchor": _anchor_at(normalised, pos),
                    },
                )
            )
            cursor = pos + 1  # the space itself is owned by the slot, not the base
        base_segments.append(normalised[cursor:])

        return CarrierPlan(
            base_segments=base_segments,
            slots=slots,
            carrier=self.name,
            notes={
                "source_bytes": len(source),
                "normalised_bytes": len(normalised),
                "stripped_existing_zwsp": len(source) != len(normalised),
                "usable_boundaries": available,
                "addressing": ADDRESSING,
            },
        )

    def assemble(self, base_segments: Sequence[bytes], chosen: Sequence[bytes]) -> bytes:
        return assemble_interleaved(base_segments, chosen)

    def extract(self, leaked: bytes, locators: Sequence[dict[str, Any]]) -> list[int | None]:
        positions = _space_positions(leaked)
        index = self._anchor_index(leaked, positions, locators)

        out: list[int | None] = []
        for loc in locators:
            k = _resolve(loc, index, len(positions))
            if k is None:
                out.append(None)
                continue
            after = positions[k] + 1
            out.append(1 if leaked[after : after + len(ZWSP)] == ZWSP else 0)
        return out

    def _anchor_index(
        self,
        leaked: bytes,
        positions: list[int],
        locators: Sequence[dict[str, Any]],
    ) -> dict[str, list[int]] | None:
        """anchor -> the space ordinals that carry it, or None if nothing needs it.

        Built once per extraction rather than once per locator: the digest work is
        linear in the number of spaces, and a thousand locators over one document
        would otherwise repeat all of it a thousand times.
        """
        if not any("anchor" in loc for loc in locators):
            return None
        stripped = self.strip_marks(leaked)
        # ZWSP carries no 0x20, so stripping preserves the count and order of spaces;
        # ordinal k means the same slot in both copies even though the offsets differ.
        stripped_positions = _space_positions(stripped)
        if len(stripped_positions) != len(positions):  # pragma: no cover - impossible
            return None
        index: dict[str, list[int]] = defaultdict(list)
        for k, pos in enumerate(stripped_positions):
            index[_anchor_at(stripped, pos)].append(k)
        return index

    def strip_marks(self, document: bytes) -> bytes:
        return document.replace(ZWSP, b"")


def _resolve(
    loc: dict[str, Any],
    index: dict[str, list[int]] | None,
    space_count: int,
) -> int | None:
    """Which space in the leaked copy this locator refers to."""
    ordinal = int(loc["word_boundary_ordinal"])
    anchor = loc.get("anchor")
    if anchor is None or index is None:
        # sealed before anchoring existed
        return ordinal if ordinal < space_count else None

    candidates = index.get(anchor)
    if not candidates:
        # the text leading up to this slot changed, or the slot was truncated away.
        # Either way the honest answer is an erasure rather than the ordinal's guess.
        return None
    if len(candidates) == 1:
        return candidates[0]
    # Repeated boilerplate produces repeated anchors, and the intended slot is the one
    # closest to where it used to be -- but only if it is close at all.
    nearest = min(candidates, key=lambda k: abs(k - ordinal))
    return nearest if abs(nearest - ordinal) <= AMBIGUOUS_DRIFT else None


def _ordinal_of(positions: list[int], pos: int) -> int:
    lo, hi = 0, len(positions)
    while lo < hi:
        mid = (lo + hi) // 2
        if positions[mid] < pos:
            lo = mid + 1
        else:
            hi = mid
    return lo


CARRIER = TextZwspCarrier()
register(CARRIER)
