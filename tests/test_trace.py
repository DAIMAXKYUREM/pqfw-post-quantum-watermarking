"""Task 6: end to end.

Build a package, distribute it, leak one recipient's copy, and get back a report that
names them -- with a p-value, a verified receipt, an intact chain and a witnessed
checkpoint. Then break each of those in turn and watch ``conclusive`` go false while
the statistics stay exactly as strong as they were. That separation is the point:
statistical certainty about *which codeword* is not the same as evidence about *which
person*.
"""

from __future__ import annotations

import numpy as np
import pytest

from pqfw import tardos, workflow
from pqfw.carrier import get_carrier
from pqfw.ledger import FixedClock
from pqfw.store import Store

SOURCE = (
    "RESTRICTED CIRCULATION. This assessment covers the procurement cycle for the "
    "current financial year and is released to the distribution list attached at "
    "annexe A. Recipients are reminded that the material below is provided for "
    "internal deliberation only. Onward transmission, reproduction, extraction of "
    "figures, or disclosure to any third party is prohibited without the written "
    "authority of the issuing office. Each copy released under this cover is "
    "individually accountable to the person named on the distribution list and can "
    "be traced back to that person if it appears outside the intended readership, "
    "which is a matter that the issuing office takes extremely seriously indeed."
).encode("utf-8")

DOC_ID = "annexe-a"
N = 20


@pytest.fixture()
def prepared(tmp_path):
    store = Store(tmp_path / "state", clock=FixedClock())
    workflow.enroll(store, recipients=N, witnesses=3, threshold=2)
    result = workflow.protect(
        store,
        SOURCE,
        doc_id=DOC_ID,
        coalition=3,
        eps1=1e-6,
        constant=100.0,
        rng=np.random.default_rng(5),
    )
    return store, result


def _open_and_checkpoint(store, recipient_id: str) -> bytes:
    opened = workflow.open_as(store, DOC_ID, recipient_id)
    workflow.checkpoint(store)
    return opened.document


# ---------------------------------------------------------------------------


def test_the_code_length_is_capped_by_the_document_and_says_so(prepared) -> None:
    """An honest cap beats a silent one. The requested code needs 12429 slots; this
    memo has a few hundred word boundaries, so the code is shortened and the report
    says by how much."""
    _store, result = prepared
    assert result.capped is True
    assert result.m == result.capacity < result.m_requested
    assert result.m_requested == tardos.code_length(3, 1e-6)


def test_end_to_end_single_leaker(prepared) -> None:
    store, _ = prepared
    leaked = _open_and_checkpoint(store, "r11")

    report = workflow.trace_leak(store, DOC_ID, leaked, alpha=1e-6)

    assert report.accused is not None
    assert report.accused.recipient_id == "r11"
    assert report.accused.accusation.p_value < 1e-6
    assert report.m_eff == report.m
    assert report.receipt_signature_valid is True
    assert report.chain_ok is True
    assert report.checkpoint_valid is True
    assert report.inclusion_proof_valid is True
    assert report.conclusive is True
    assert report.verdict == "IDENTIFIED"


def test_two_decryptions_by_one_person_are_forensically_distinct(prepared) -> None:
    """The spec asks for a watermark specific to each recipient *and decryption session*.

    Before session credentials existed, a person who opened the document twice got
    byte-identical copies and an identical ledger commitment, so a leak was
    attributable to the person but not to the event. Each decryption now spends its own
    credential, carrying its own codeword.
    """
    store, _ = prepared

    first = workflow.open_as(store, DOC_ID, "r04")
    second = workflow.open_as(store, DOC_ID, "r04")
    workflow.checkpoint(store)

    assert first.session_id != second.session_id
    assert first.document != second.document, "two sessions must not produce one file"
    assert first.doc_hash != second.doc_hash

    record = store.doc(DOC_ID)
    assert record.commitments[first.session_id] != record.commitments[second.session_id]

    # and each leaked copy resolves to its own decryption event
    for opened in (first, second):
        report = workflow.trace_leak(store, DOC_ID, opened.document)
        assert report.accused is not None
        assert report.accused.recipient_id == "r04"
        assert report.accused.session_id == opened.session_id
        assert report.ledger_seq == opened.ledger_seq
        assert report.conclusive is True

    assert first.ledger_seq != second.ledger_seq


def test_a_recipient_cannot_decrypt_more_times_than_they_hold_credentials(prepared) -> None:
    """The pool is finite by design, and running out is a refusal rather than a reused
    fingerprint."""
    store, _ = prepared
    issued = len(store.doc(DOC_ID).sessions_for("r19"))
    for _ in range(issued):
        workflow.open_as(store, DOC_ID, "r19")
    with pytest.raises(ValueError, match="spent all"):
        workflow.open_as(store, DOC_ID, "r19")


def test_the_report_always_carries_a_p_value_and_the_runners_up(prepared) -> None:
    """Never a bare 'the leaker is recipient 4'."""
    store, _ = prepared
    leaked = _open_and_checkpoint(store, "r03")
    report = workflow.trace_leak(store, DOC_ID, leaked)

    payload = report.to_json()
    assert payload["accused"]["p_value"] is not None
    assert payload["accused"]["log10_p_value"] < 0
    assert payload["m_eff"] == payload["m"]
    assert len(payload["runners_up"]) == 4
    top = payload["accused"]["z_score"]
    assert all(r["z_score"] < top for r in payload["runners_up"])


def test_end_to_end_collusion_of_three(prepared) -> None:
    """Three recipients splice their copies together slot by slot.

    Where all three agree they are stuck: none of them holds the key for the other
    rendering. Where they disagree they can take a majority vote. The code is built
    for exactly this.
    """
    store, _ = prepared
    carrier = get_carrier("text-zwsp")
    record = store.doc(DOC_ID)
    coalition = ["r02", "r07", "r15"]

    copies = [_open_and_checkpoint(store, rid) for rid in coalition]
    bits = np.array([carrier.extract(c, record.locators) for c in copies], dtype=np.uint8)
    forged = tardos.collude(bits, "majority", np.random.default_rng(9))

    from pqfw.trace import trace_bits

    suspects = [s.recipient_id for s in trace_bits(forged, DOC_ID, store)[:3]]
    assert set(suspects) & set(coalition), f"no colluder in the top three: {suspects}"


def test_innocent_document_not_accused(prepared) -> None:
    """An unmarked copy of the same text names nobody.

    The extracted bits are all zero, which is not close to any issued codeword -- and
    the report says NO IDENTIFICATION rather than picking whoever scored highest.
    """
    store, _ = prepared
    _open_and_checkpoint(store, "r05")

    report = workflow.trace_leak(store, DOC_ID, SOURCE, alpha=1e-6)

    assert report.statistically_significant is False
    assert report.conclusive is False
    assert report.verdict == "NO IDENTIFICATION"
    assert report.accused is not None, "we still report the highest scorer, with its p-value"
    assert report.accused.accusation.p_value >= 1e-6


def test_a_stripped_copy_names_nobody(prepared) -> None:
    """The documented carrier attack: an editor that removes zero-width characters.

    The result must be a failure to identify, not a misidentification.
    """
    store, _ = prepared
    leaked = _open_and_checkpoint(store, "r09")
    carrier = get_carrier("text-zwsp")

    report = workflow.trace_leak(store, DOC_ID, carrier.strip_marks(leaked))
    assert report.conclusive is False
    assert report.verdict == "NO IDENTIFICATION"


def test_truncation_weakens_the_evidence_without_inventing_any(prepared) -> None:
    store, _ = prepared
    leaked = _open_and_checkpoint(store, "r13")

    full = workflow.trace_leak(store, DOC_ID, leaked)
    half = workflow.trace_leak(store, DOC_ID, leaked[: len(leaked) // 2])

    assert half.accused is not None and half.accused.recipient_id == "r13"
    assert half.m_eff < full.m_eff
    assert half.accused.accusation.z_score < full.accused.accusation.z_score
    assert any("unreadable" in note for note in half.notes)


def test_tampered_ledger_blocks_conclusion(prepared) -> None:
    """Correct tracing plus a broken chain is not a positive identification."""
    store, _ = prepared
    leaked = _open_and_checkpoint(store, "r08")
    assert workflow.trace_leak(store, DOC_ID, leaked).conclusive is True

    workflow.tamper(store, seq=0, field="doc_hash")

    report = workflow.trace_leak(store, DOC_ID, leaked)
    assert report.statistically_significant is True, "the marks did not change"
    assert report.chain_ok is False
    assert report.conclusive is False
    assert report.verdict == "UNCORROBORATED"


def test_a_leak_with_no_receipt_is_not_a_positive_identification(prepared) -> None:
    """Someone else opened the package; the accused never did.

    The marks say r17, but no receipt in the ledger carries r17's commitment, so the
    trace stops short of naming them.
    """
    store, _ = prepared
    package_holder = "r17"
    store_doc = store.doc(DOC_ID)
    carrier = get_carrier("text-zwsp")

    # forge the copy directly from a sealed codeword, without anybody decrypting it
    from pqfw import package as pkg

    unspent_session = store_doc.sessions_for(package_holder)[0]
    plan_bits = store_doc.X[store_doc.index_of(unspent_session)]
    reference = workflow.open_as(store, DOC_ID, "r00").document
    forged = _rebuild_with_bits(reference, store_doc.locators, plan_bits, carrier)
    del pkg

    workflow.checkpoint(store)
    report = workflow.trace_leak(store, DOC_ID, forged)

    assert report.accused is not None and report.accused.recipient_id == package_holder
    assert report.statistically_significant is True
    assert report.ledger_seq is None
    assert report.conclusive is False
    assert any("never signed a decryption receipt" in n for n in report.notes)


def test_a_trace_before_any_checkpoint_is_not_conclusive(prepared) -> None:
    """An entry nobody has witnessed yet can still be rewritten wholesale."""
    store, _ = prepared
    opened = workflow.open_as(store, DOC_ID, "r04")

    report = workflow.trace_leak(store, DOC_ID, opened.document)
    assert report.receipt_signature_valid is True
    assert report.chain_ok is True
    assert report.checkpoint_valid is False
    assert report.conclusive is False
    assert any("not covered by a witness checkpoint" in n for n in report.notes)

    workflow.checkpoint(store)
    assert workflow.trace_leak(store, DOC_ID, opened.document).conclusive is True


def test_state_survives_a_process_restart(prepared, tmp_path) -> None:
    """Tracing months later, from a store on disk and nothing in memory."""
    store, _ = prepared
    leaked = _open_and_checkpoint(store, "r06")

    reopened = Store.open(tmp_path / "state", clock=FixedClock())
    report = workflow.trace_leak(reopened, DOC_ID, leaked)
    assert report.accused is not None and report.accused.recipient_id == "r06"
    assert report.conclusive is True


def test_the_sealed_store_is_not_readable_without_its_key(prepared, tmp_path) -> None:
    from cryptography.exceptions import InvalidTag

    store, _ = prepared
    raw = store.sealed_path.read_bytes()
    assert b"recipient_order" not in raw and b"r11" not in raw

    (tmp_path / "state" / "seal.key").write_bytes(b"\x00" * 32)
    with pytest.raises(InvalidTag):
        Store.open(tmp_path / "state")


def _rebuild_with_bits(reference: bytes, locators, bits, carrier) -> bytes:
    """Rewrite an existing copy so that its marks read as ``bits``.

    Only possible here because the test is standing in the distributor's shoes with the
    sealed store open. A recipient cannot do this: they hold one variant key per slot
    and the AEAD tag stops them producing the other rendering.
    """
    from pqfw.carriers.text import ZWSP

    stripped = carrier.strip_marks(reference)
    positions = [i for i, byte in enumerate(stripped) if byte == 0x20]
    wanted = {int(loc["word_boundary_ordinal"]): int(b) for loc, b in zip(locators, bits)}

    out = bytearray()
    cursor = 0
    for ordinal in sorted(wanted):
        index = positions[ordinal]
        out += stripped[cursor : index + 1]
        if wanted[ordinal]:
            out += ZWSP
        cursor = index + 1
    out += stripped[cursor:]
    return bytes(out)
