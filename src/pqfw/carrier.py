"""What a "mark slot" is, independent of the file format it lives in.

The crypto in package.py never learns whether a slot is a space in a text file or a
kern in a PDF content stream. It only knows that a slot has two byte strings that a
reader cannot tell apart, and that given a leaked file someone can walk back and say
which of the two is present.

Keeping this seam clean is what let the PDF carrier arrive in Phase 2 without a single
line changing in package.py, ledger.py or trace.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Sequence, runtime_checkable

import numpy as np


@dataclass(frozen=True)
class Slot:
    index: int
    variant_0: bytes
    """Rendering used when the recipient's codeword bit is 0."""
    variant_1: bytes
    """Rendering used when the codeword bit is 1. Must be visually identical to
    variant_0 in the intended viewer."""
    locator: dict[str, Any]
    """Carrier-specific information needed to find this slot again in a leaked copy.
    JSON-serialisable: it is written to the distributor's sealed store."""


@dataclass(frozen=True)
class CarrierPlan:
    base_segments: list[bytes]
    """Length m + 1. document = base[0] + slot[0] + base[1] + slot[1] + ... + base[m]."""
    slots: list[Slot]
    carrier: str = "unknown"
    notes: dict[str, Any] | None = None
    """Anything the carrier wants to record about how it planned, e.g. whether the
    source had to be normalised first."""

    def __post_init__(self) -> None:
        if len(self.base_segments) != len(self.slots) + 1:
            raise ValueError(
                f"a plan with {len(self.slots)} slots needs {len(self.slots) + 1} base "
                f"segments, got {len(self.base_segments)}"
            )

    @property
    def m(self) -> int:
        return len(self.slots)

    def locators(self) -> list[dict[str, Any]]:
        return [s.locator for s in self.slots]


@runtime_checkable
class MarkCarrier(Protocol):
    """A format that can hold m invisible one-bit marks."""

    name: str

    def capacity(self, source: bytes) -> int:
        """How many slots this source can hold. The CLI caps the Tardos code length
        by this, and says so, rather than silently producing a shorter code."""
        ...

    def plan(self, source: bytes, m: int, rng: np.random.Generator) -> CarrierPlan:
        ...

    def assemble(self, base_segments: Sequence[bytes], chosen: Sequence[bytes]) -> bytes:
        ...

    def extract(self, leaked: bytes, locators: Sequence[dict[str, Any]]) -> list[int | None]:
        """One entry per locator: 0, 1, or None when the slot could not be read.

        None is not a guess. A carrier that returns 0 for an unreadable slot corrupts
        the accusation score in a way that looks exactly like evidence.
        """
        ...

    def strip_marks(self, document: bytes) -> bytes:
        """The document with all marking artefacts removed.

        Used to prove visual equivalence in tests: two recipients' copies must be
        equal after stripping.
        """
        ...


_REGISTRY: dict[str, MarkCarrier] = {}


def register(carrier: MarkCarrier) -> MarkCarrier:
    _REGISTRY[carrier.name] = carrier
    return carrier


def get_carrier(name: str) -> MarkCarrier:
    if name not in _REGISTRY:
        raise KeyError(f"unknown carrier {name!r}; available: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def available() -> list[str]:
    return sorted(_REGISTRY)


def assemble_interleaved(base_segments: Sequence[bytes], chosen: Sequence[bytes]) -> bytes:
    """The one assembly rule every carrier shares."""
    if len(base_segments) != len(chosen) + 1:
        raise ValueError(
            f"{len(chosen)} chosen variants need {len(chosen) + 1} base segments, "
            f"got {len(base_segments)}"
        )
    out = bytearray(base_segments[0])
    for variant, segment in zip(chosen, base_segments[1:]):
        out += variant
        out += segment
    return bytes(out)
