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
