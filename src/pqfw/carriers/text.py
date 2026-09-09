"""Zero-width-space text carrier.

A slot is one inter-word space. The two variants are:

    variant_0 = b" "                 (U+0020)
    variant_1 = b" \\xe2\\x80\\x8b"     (U+0020 followed by U+200B ZERO WIDTH SPACE)

Both render identically in a browser, in a terminal, in Word, and on paper.

Why the ordinal is the count of U+0020 characters
-------------------------------------------------
A slot's locator is "the k-th space character in the document". Marking a slot appends
a zero-width space *after* the U+0020; it neither adds nor removes a U+0020. So the
ordinal of every other slot is unchanged by marking, and extraction on a marked copy
enumerates exactly the same positions the planner did. Truncation removes a suffix of
the ordinals, which is why a cut document yields None for its tail rather than garbage
for the whole thing.

In UTF-8, byte 0x20 only ever occurs as the space character -- continuation bytes are
all >= 0x80 -- so this counting can be done on raw bytes without decoding, and survives
a document that is not valid UTF-8 at all.

Threat model (honest version, and it belongs in the README too)
---------------------------------------------------------------
This carrier survives: redistribution of the file itself, copying into anything that
preserves the byte stream, email attachment, and archive/compress round-trips.

This carrier does NOT survive: pasting through an editor that normalises whitespace,
retyping, OCR of a scan, or any "strip invisible characters" tool. Those are real
attacks and the evaluation harness measures every one of them. The declared threat
model is redistribution of the artefact, not manual reconstruction of its content.
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np

from pqfw.carrier import CarrierPlan, Slot, assemble_interleaved, register

SPACE = b" "
ZWSP = "​".encode("utf-8")  # b"\xe2\x80\x8b"

VARIANT_0 = SPACE
VARIANT_1 = SPACE + ZWSP


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
                    locator={"carrier": self.name, "word_boundary_ordinal": ordinal},
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
            },
        )

    def assemble(self, base_segments: Sequence[bytes], chosen: Sequence[bytes]) -> bytes:
        return assemble_interleaved(base_segments, chosen)

    def extract(self, leaked: bytes, locators: Sequence[dict[str, Any]]) -> list[int | None]:
        positions = _space_positions(leaked)
        out: list[int | None] = []
        for loc in locators:
            k = int(loc["word_boundary_ordinal"])
            if k >= len(positions):
                out.append(None)  # truncated away
                continue
            after = positions[k] + 1
            out.append(1 if leaked[after : after + len(ZWSP)] == ZWSP else 0)
        return out

    def strip_marks(self, document: bytes) -> bytes:
        return document.replace(ZWSP, b"")


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
