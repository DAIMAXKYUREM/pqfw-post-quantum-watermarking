"""Task 5: the append-only decryption ledger.

Four kinds of history rewriting, all of which must be detected and *located*:
editing a record, deleting an entry, reordering entries, and forging a checkpoint.
Plus the property that makes the ledger safe to publish: it contains a commitment to
each codeword and never the codeword.
"""

from __future__ import annotations

import base64

import pytest

from pqfw import ledger as L
from pqfw import pqc
from pqfw.ledger import FixedClock, Ledger


def _recipient(rid: str):
    sig_pk, sig_sk = pqc.sig_keypair()
    return rid, sig_pk, sig_sk


def _receipt(ledger: Ledger, rid: str, sig_pk: bytes, sig_sk: bytes, n: int = 0):
    commitment = L.codeword_commitment([1, 0, 1, 1, 0], salt=bytes([n]) * 16)
    record = L.build_receipt(
        doc_id="doc-1",
        recipient_id=rid,
        session_id=f"{rid}#0",
        recipient_sig_pk=sig_pk,
        doc_hash=pqc.sha3_hex(f"copy-{rid}".encode()),
        commitment=commitment,
        clock=ledger.clock,
        nonce=bytes([n]) * 16,
    )
    return record, L.sign_receipt(record, sig_sk)


def _populate(count: int = 5) -> tuple[Ledger, list[tuple[str, bytes, bytes]]]:
    ledger = Ledger(clock=FixedClock())
    people = [_recipient(f"r{i:02d}") for i in range(count)]
    for i, (rid, pk, sk) in enumerate(people):
        record, sig = _receipt(ledger, rid, pk, sk, n=i)
        ledger.append(record, sig, pk)
    return ledger, people


def _witnesses(n: int = 3):
    return [pqc.sig_keypair() for _ in range(n)]


# ---------------------------------------------------------------------------
# chain
# ---------------------------------------------------------------------------


def test_append_and_verify_chain() -> None:
    ledger, _ = _populate()
    report = ledger.verify_chain()
    assert report.ok is True
    assert report.entries == 5
    assert report.first_bad_seq is None
    assert ledger.entries[0].prev_hash == L.GENESIS_HASH
    for previous, current in zip(ledger.entries, ledger.entries[1:]):
        assert current.prev_hash == previous.entry_hash


def test_append_rejects_bad_signature() -> None:
    ledger = Ledger(clock=FixedClock())
    rid, pk, sk = _recipient("r00")
    record, sig = _receipt(ledger, rid, pk, sk)

    forged = bytearray(sig)
    forged[10] ^= 0xFF
    with pytest.raises(ValueError, match="does not verify"):
        ledger.append(record, bytes(forged), pk)

    other_pk, _ = pqc.sig_keypair()
    with pytest.raises(ValueError, match="different signing key"):
        ledger.append(record, sig, other_pk)

    assert ledger.entries == []


def test_append_rejects_a_receipt_signed_for_a_different_document() -> None:
    """A receipt is only evidence about the copy whose hash it names."""
    ledger = Ledger(clock=FixedClock())
    rid, pk, sk = _recipient("r00")
    record, sig = _receipt(ledger, rid, pk, sk)
    record["doc_hash"] = pqc.sha3_hex(b"some other copy")
    with pytest.raises(ValueError, match="does not verify"):
        ledger.append(record, sig, pk)


def test_tampered_record_detected() -> None:
    ledger, _ = _populate()
    ledger.entries[2].record["doc_hash"] = pqc.sha3_hex(b"a copy nobody released")

    report = ledger.verify_chain()
    assert report.ok is False
    assert report.first_bad_seq == 2
    assert any("altered" in p for p in report.problems)


def test_tampered_record_with_recomputed_hash_still_fails_on_the_signature() -> None:
    """The realistic attack: an administrator who edits a record also recomputes every
    hash after it. The chain then links up perfectly -- and the recipient's ML-DSA
    signature over the record does not, because the administrator does not hold the
    recipient's key."""
    ledger, _ = _populate()
    ledger.entries[1].record["recipient_id"] = "r04"
    for i, entry in enumerate(ledger.entries):
        entry.prev_hash = L.GENESIS_HASH if i == 0 else ledger.entries[i - 1].entry_hash
        entry.entry_hash = entry.compute_hash()

    report = ledger.verify_chain()
    assert report.ok is False
    assert report.first_bad_seq == 1
    assert any("signature does not verify" in p for p in report.problems)


def test_deleted_entry_detected() -> None:
    ledger, _ = _populate()
    del ledger.entries[3]

    report = ledger.verify_chain()
    assert report.ok is False
    assert report.first_bad_seq == 4
    assert any("prev_hash" in p for p in report.problems)


def test_reordered_entries_detected() -> None:
    ledger, _ = _populate()
    ledger.entries[1], ledger.entries[3] = ledger.entries[3], ledger.entries[1]

    report = ledger.verify_chain()
    assert report.ok is False
    assert report.first_bad_seq == 1


def test_truncating_the_tail_is_detected_by_the_checkpoint_not_the_chain() -> None:
    """Cutting entries off the end leaves a valid chain -- that is the known limit of a
    hash chain, and precisely why checkpoints exist. The signed root still covers the
    deleted entries, so the inclusion proof fails and the tampering surfaces."""
    ledger, _ = _populate()
    witnesses = _witnesses()
    cp = ledger.checkpoint([sk for _pk, sk in witnesses], k=2)
    assert ledger.verify_chain().ok is True

    del ledger.entries[3:]
    assert ledger.verify_chain().ok is True, "a hash chain cannot see its own tail go"

    covered = [e.entry_hash for e in ledger.entries if cp.from_seq <= e.seq <= cp.to_seq]
    assert L.merkle_root(covered) != cp.root
    assert ledger.verify_checkpoint(cp, [pk for pk, _sk in witnesses], k=2) is True


# ---------------------------------------------------------------------------
# checkpoints
# ---------------------------------------------------------------------------


def test_checkpoint_requires_k_witnesses() -> None:
    ledger, _ = _populate()
    witnesses = _witnesses(3)
    public = [pk for pk, _ in witnesses]

    one = ledger.checkpoint([witnesses[0][1]], k=1)
    assert ledger.verify_checkpoint(one, public, k=1) is True
    assert ledger.verify_checkpoint(one, public, k=2) is False

    rid, pk, sk = _recipient("r99")
    record, sig = _receipt(ledger, rid, pk, sk, n=9)
    ledger.append(record, sig, pk)

    two = ledger.checkpoint([witnesses[0][1], witnesses[1][1]], k=2)
    assert ledger.verify_checkpoint(two, public, k=2) is True
    assert ledger.verify_checkpoint(two, public, k=3) is False


def test_a_forged_root_fails_with_every_witness_signature_present() -> None:
    """Rewriting the root invalidates all three signatures at once: they were made
    over the old root, and the administrator cannot remake them."""
    import dataclasses

    ledger, _ = _populate()
    witnesses = _witnesses(3)
    cp = ledger.checkpoint([sk for _pk, sk in witnesses], k=2)
    public = [pk for pk, _sk in witnesses]
    assert ledger.count_witnesses(cp, public) == 3

    forged = dataclasses.replace(cp, root=pqc.sha3_hex(b"a more convenient history"))
    assert ledger.count_witnesses(forged, public) == 0
    assert ledger.verify_checkpoint(forged, public, k=1) is False


def test_unrecognised_witnesses_do_not_count() -> None:
    """An administrator who generates their own witness keys gains nothing."""
    ledger, _ = _populate()
    real = _witnesses(3)
    impostors = _witnesses(5)
    cp = ledger.checkpoint([sk for _pk, sk in impostors], k=1)
    assert ledger.count_witnesses(cp, [pk for pk, _ in real]) == 0


def test_the_same_witness_twice_is_one_witness() -> None:
    ledger, _ = _populate()
    (pk, sk), *_ = _witnesses(1)
    cp = ledger.checkpoint([sk, sk, sk], k=1)
    assert ledger.count_witnesses(cp, [pk]) == 1
    assert ledger.verify_checkpoint(cp, [pk], k=2) is False


def test_checkpoints_chain_to_each_other() -> None:
    ledger, _ = _populate(3)
    witnesses = _witnesses()
    keys = [sk for _pk, sk in witnesses]
    first = ledger.checkpoint(keys, k=2)
    assert first.prev_root == L.GENESIS_HASH

    rid, pk, sk = _recipient("r50")
    record, sig = _receipt(ledger, rid, pk, sk, n=50)
    ledger.append(record, sig, pk)
    second = ledger.checkpoint(keys, k=2)

    assert second.prev_root == first.root
    assert second.from_seq == first.to_seq + 1
    with pytest.raises(ValueError, match="nothing to checkpoint"):
        ledger.checkpoint(keys, k=2)


# ---------------------------------------------------------------------------
# Merkle
# ---------------------------------------------------------------------------


def test_merkle_inclusion_proof() -> None:
    ledger, _ = _populate(5)
    witnesses = _witnesses()
    cp = ledger.checkpoint([sk for _pk, sk in witnesses], k=2)

    for entry in ledger.entries:
        checkpoint, proof = ledger.inclusion_proof(entry.seq)
        assert checkpoint.root == cp.root
        assert L.verify_merkle_proof(entry.entry_hash, proof, cp.root) is True

    forged = pqc.sha3_hex(b"an entry that was never appended")
    _cp, proof = ledger.inclusion_proof(0)
    assert L.verify_merkle_proof(forged, proof, cp.root) is False


def test_merkle_root_handles_odd_leaf_counts() -> None:
    hashes = [pqc.sha3_hex(bytes([i])) for i in range(7)]
    root = L.merkle_root(hashes)
    assert len(root) == 64
    for i in range(7):
        assert L.verify_merkle_proof(hashes[i], L.merkle_proof(hashes, i), root) is True


def test_merkle_leaves_and_nodes_are_domain_separated() -> None:
    """An internal node must not be presentable as a leaf. Without the prefix bytes a
    two-leaf tree's root equals the hash of its children concatenated, which lets a
    forger pass off a node as a leaf."""
    a, b = pqc.sha3_hex(b"a"), pqc.sha3_hex(b"b")
    root = L.merkle_root([a, b])
    assert L.merkle_root([root]) != root


# ---------------------------------------------------------------------------
# privacy, lookup, persistence
# ---------------------------------------------------------------------------


def test_the_ledger_never_contains_a_codeword() -> None:
    """The property that lets the ledger be published in full."""
    ledger, _ = _populate()
    blob = pqc.canonical(ledger.to_json())
    for entry in ledger.entries:
        assert set(entry.record) == {
            "doc_id",
            "recipient_id",
            "session_id",
            "recipient_sig_pk_fpr",
            "timestamp",
            "doc_hash",
            "codeword_commitment",
            "nonce",
        }
    assert b"codeword" not in blob.replace(b"codeword_commitment", b"")


def test_commitment_hides_the_codeword_and_the_salt_prevents_guessing() -> None:
    codeword = [1, 0, 1, 1, 0]
    a = L.codeword_commitment(codeword, salt=b"\x01" * 16)
    b = L.codeword_commitment(codeword, salt=b"\x02" * 16)
    assert a != b, "the same codeword under two salts must not be linkable"
    assert a == L.codeword_commitment(codeword, salt=b"\x01" * 16)
    assert a != L.codeword_commitment([1, 0, 1, 1, 1], salt=b"\x01" * 16)


def test_find_by_commitment() -> None:
    ledger, _ = _populate()
    wanted = ledger.entries[3].record["codeword_commitment"]
    found = ledger.find_by_commitment(wanted)
    assert found is not None and found.seq == 3
    assert ledger.find_by_commitment(pqc.sha3_hex(b"nope")) is None


def test_ledger_survives_a_disk_roundtrip(tmp_path) -> None:
    ledger, _ = _populate()
    witnesses = _witnesses()
    cp = ledger.checkpoint([sk for _pk, sk in witnesses], k=2)

    path = tmp_path / "ledger.json"
    ledger.save(path)
    reloaded = Ledger.load(path)

    assert reloaded.verify_chain().ok is True
    assert reloaded.checkpoints[0].root == cp.root
    assert reloaded.verify_checkpoint(
        reloaded.checkpoints[0], [pk for pk, _ in witnesses], k=2
    )


def test_loading_a_missing_ledger_gives_an_empty_one(tmp_path) -> None:
    ledger = Ledger.load(tmp_path / "nothing-here.json")
    assert ledger.entries == [] and ledger.verify_chain().ok is True


def test_checkpoint_qr_export(tmp_path) -> None:
    ledger, _ = _populate()
    cp = ledger.checkpoint([sk for _pk, sk in _witnesses()], k=2)
    anchor = L.checkpoint_anchor(cp)
    assert cp.root in anchor and anchor.startswith("PQFW1|")

    out = L.export_checkpoint_qr(cp, tmp_path / "anchor.png")
    assert out.exists() and out.stat().st_size > 0
    assert out.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_entry_carries_its_own_public_key_so_verification_is_standalone() -> None:
    ledger, people = _populate(2)
    entry = ledger.entries[0]
    pk = base64.b64decode(entry.recipient_sig_pk)
    assert pk == people[0][1]
    assert entry.signature_is_valid() is True
