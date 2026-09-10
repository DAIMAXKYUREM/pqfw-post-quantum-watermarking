"""Task 3: the zero-width-space text carrier.

The properties that matter:
  * an all-zero assembly is byte-identical to the source (so the unmarked document is
    the real document, not a lookalike),
  * two recipients' copies differ only in invisible characters,
  * extraction recovers the exact bit vector,
  * and a truncated copy yields None for its tail rather than a plausible-looking 0.
"""

from __future__ import annotations

import numpy as np
import pytest

from pqfw.carrier import get_carrier
from pqfw.carriers.text import VARIANT_0, VARIANT_1, ZWSP

SOURCE = (
    "MEMORANDUM. Distribution is restricted to the named recipients below. "
    "Any redistribution of this document, in whole or in part, is a breach of the "
    "terms under which it was released. The contents summarise an internal review "
    "of procurement irregularities identified during the last audit cycle and are "
    "not for external circulation under any circumstances whatsoever, ever."
).encode("utf-8")


def carrier():
    return get_carrier("text-zwsp")


def rng(seed: int = 0) -> np.random.Generator:
    return np.random.default_rng(seed)


def test_plan_produces_m_slots_and_all_zero_assembly_is_the_source() -> None:
    c = carrier()
    plan = c.plan(SOURCE, m=20, rng=rng())
    assert plan.m == 20
    assert len(plan.base_segments) == 21
    rebuilt = c.assemble(plan.base_segments, [s.variant_0 for s in plan.slots])
    assert rebuilt == SOURCE


def test_capacity_matches_the_number_of_word_boundaries() -> None:
    c = carrier()
    assert c.capacity(SOURCE) == SOURCE.count(b" ")
    with pytest.raises(ValueError):
        c.plan(SOURCE, m=c.capacity(SOURCE) + 1, rng=rng())


def test_visual_equivalence() -> None:
    """Strip the marking character and every recipient holds the same document."""
    c = carrier()
    plan = c.plan(SOURCE, m=24, rng=rng())
    all_zero = c.assemble(plan.base_segments, [s.variant_0 for s in plan.slots])
    all_one = c.assemble(plan.base_segments, [s.variant_1 for s in plan.slots])

    assert all_zero != all_one
    assert c.strip_marks(all_one) == all_zero
    assert len(all_one) == len(all_zero) + 24 * len(ZWSP)
    # and the visible text is identical once decoded
    assert all_one.decode("utf-8").replace("​", "") == all_zero.decode("utf-8")


def test_extract_roundtrip() -> None:
    c = carrier()
    m = 30
    plan = c.plan(SOURCE, m=m, rng=rng(1))
    bits = (rng(2).random(m) < 0.5).astype(int).tolist()
    doc = c.assemble(
        plan.base_segments, [VARIANT_1 if b else VARIANT_0 for b in bits]
    )
    assert c.extract(doc, plan.locators()) == bits


def test_extract_is_stable_across_two_different_bit_vectors() -> None:
    """Slot k must read slot k regardless of what the other slots hold -- the whole
    point of counting U+0020, which marking never changes."""
    c = carrier()
    m = 30
    plan = c.plan(SOURCE, m=m, rng=rng(3))
    for seed in (4, 5, 6):
        bits = (rng(seed).random(m) < 0.5).astype(int).tolist()
        doc = c.assemble(plan.base_segments, [VARIANT_1 if b else VARIANT_0 for b in bits])
        assert c.extract(doc, plan.locators()) == bits


def test_extract_with_truncation() -> None:
    c = carrier()
    m = 30
    plan = c.plan(SOURCE, m=m, rng=rng(7))
    bits = (rng(8).random(m) < 0.5).astype(int).tolist()
    doc = c.assemble(plan.base_segments, [VARIANT_1 if b else VARIANT_0 for b in bits])

    truncated = doc[: int(len(doc) * 0.7)]
    got = c.extract(truncated, plan.locators())

    assert None in got, "cutting the tail must produce erasures"
    readable = [i for i, v in enumerate(got) if v is not None]
    assert readable == list(range(len(readable))), "erasures must be a suffix"
    assert all(got[i] == bits[i] for i in readable), "the surviving head must be correct"
    assert len(readable) >= m // 2


def test_whitespace_normalisation_destroys_the_marks_and_we_say_so() -> None:
    """The documented failure mode, asserted rather than hoped for.

    An editor that strips zero-width characters leaves a document that reads as
    all-zeros. Tracing must therefore be unable to name anybody -- which it cannot,
    since an all-zero read is not close to any particular codeword. Recording the
    failure here keeps it from being discovered in a demo.
    """
    c = carrier()
    m = 30
    plan = c.plan(SOURCE, m=m, rng=rng(9))
    bits = [1] * m
    doc = c.assemble(plan.base_segments, [VARIANT_1 if b else VARIANT_0 for b in bits])
    laundered = doc.replace(ZWSP, b"")
    assert c.extract(laundered, plan.locators()) == [0] * m


def test_preexisting_zero_width_spaces_are_normalised_away() -> None:
    c = carrier()
    dirty = b"alpha " + ZWSP + b"beta gamma delta epsilon zeta"
    plan = c.plan(dirty, m=3, rng=rng(10))
    assert plan.notes is not None and plan.notes["stripped_existing_zwsp"] is True
    clean = c.assemble(plan.base_segments, [s.variant_0 for s in plan.slots])
    assert ZWSP not in clean
    assert c.extract(clean, plan.locators()) == [0, 0, 0]


def test_locators_are_json_serialisable() -> None:
    import json

    plan = carrier().plan(SOURCE, m=5, rng=rng(11))
    assert json.loads(json.dumps(plan.locators())) == plan.locators()


# --- content-anchored slot addressing ---------------------------------------------
#
# An ordinal locator says "the k-th space in the document", so inserting or deleting a
# single word ahead of a slot shifts every ordinal after it and the extractor reads its
# neighbours instead. The evaluation harness measured that as two of the four attacks
# that defeat the carrier. A locator anchored to the content that precedes the slot is
# unmoved by an edit somewhere else in the document.

LONG_SOURCE = (SOURCE + b" ") * 6


def _bits(n: int, seed: int = 7) -> list[int]:
    return [int(b) for b in np.random.default_rng(seed).integers(0, 2, size=n)]


def _marked(c, plan, bits):
    chosen = [s.variant_1 if b else s.variant_0 for s, b in zip(plan.slots, bits)]
    return c.assemble(plan.base_segments, chosen)


def test_every_locator_carries_a_content_anchor() -> None:
    c = carrier()
    plan = c.plan(LONG_SOURCE, m=40, rng=rng())
    for slot in plan.slots:
        assert isinstance(slot.locator["anchor"], str)
        assert len(slot.locator["anchor"]) == 12
        # the ordinal stays, both for the nearest-match tie-break and so that packages
        # sealed before anchoring still open
        assert "word_boundary_ordinal" in slot.locator


def test_a_word_inserted_at_the_start_no_longer_shifts_every_slot() -> None:
    c = carrier()
    plan = c.plan(LONG_SOURCE, m=40, rng=rng())
    bits = _bits(40)
    attacked = b"NOTE " + _marked(c, plan, bits)

    recovered = c.extract(attacked, plan.locators())
    agree = sum(1 for got, want in zip(recovered, bits) if got == want)
    # every slot but the handful whose own preceding window contains the insertion
    assert agree >= 37, f"only {agree}/40 slots survived a one-word prefix"


def test_deleting_the_first_word_no_longer_shifts_every_slot() -> None:
    c = carrier()
    plan = c.plan(LONG_SOURCE, m=40, rng=rng())
    bits = _bits(40)
    marked = _marked(c, plan, bits)
    first = marked.find(b" ")
    second = marked.find(b" ", first + 1)
    attacked = marked[:first] + marked[second:]

    recovered = c.extract(attacked, plan.locators())
    agree = sum(1 for got, want in zip(recovered, bits) if got == want)
    assert agree >= 37, f"only {agree}/40 slots survived a deleted first word"


def test_an_edit_beside_one_slot_erases_that_slot_and_not_the_rest() -> None:
    """A lost slot must read as None, never as a guess.

    An erasure drops out of the Tardos sum; a wrong bit actively pushes the true
    leaker's score down. So when the anchor cannot be found the honest answer is
    "unreadable", which is the same failure mode the whole system is built around.
    """
    c = carrier()
    plan = c.plan(LONG_SOURCE, m=40, rng=rng())
    bits = _bits(40)
    marked = _marked(c, plan, bits)

    # rewrite the words immediately before slot 20, leaving the rest untouched
    target = _space_offsets(marked)[int(plan.slots[20].locator["word_boundary_ordinal"])]
    attacked = marked[: target - 24] + b" qqqq wwww eeee rrrr ss " + marked[target:]

    recovered = c.extract(attacked, plan.locators())
    assert recovered[20] is None
    survivors = sum(1 for i, (got, want) in enumerate(zip(recovered, bits))
                    if i != 20 and got == want)
    assert survivors >= 36


def test_truncation_still_erases_the_tail() -> None:
    c = carrier()
    plan = c.plan(LONG_SOURCE, m=40, rng=rng())
    marked = _marked(c, plan, _bits(40))
    recovered = c.extract(marked[: len(marked) // 2], plan.locators())
    assert recovered[-1] is None
    assert any(bit is not None for bit in recovered[:10])


def test_a_locator_without_an_anchor_still_extracts() -> None:
    """Packages sealed before this change carry ordinals only."""
    c = carrier()
    plan = c.plan(LONG_SOURCE, m=40, rng=rng())
    bits = _bits(40)
    marked = _marked(c, plan, bits)
    legacy = [{"carrier": loc["carrier"],
               "word_boundary_ordinal": loc["word_boundary_ordinal"]}
              for loc in plan.locators()]
    assert c.extract(marked, legacy) == bits


def test_repeated_boilerplate_resolves_to_the_nearest_ordinal() -> None:
    """Identical passages give identical anchors; the ordinal breaks the tie."""
    c = carrier()
    boilerplate = b"this page is intentionally left blank and says nothing at all. "
    source = boilerplate * 12
    plan = c.plan(source, m=24, rng=rng())
    bits = _bits(24)
    assert c.extract(_marked(c, plan, bits), plan.locators()) == bits


def _space_offsets(document: bytes) -> list[int]:
    from pqfw.carriers.text import _space_positions

    return _space_positions(document)
