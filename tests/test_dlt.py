"""The permissioned distributed ledger.

The requirement is that no single administrator or compromised account can retroactively
alter or erase a record. A single hash chain cannot deliver that -- one holder means one
administrator. These tests are about what replication buys:

  * every validator independently re-verifies a receipt before holding it,
  * a block commits only at quorum,
  * a validator will not sign a block its own replica cannot reproduce,
  * and compromising one node is detected and out-voted.
"""

from __future__ import annotations

import pytest

from pqfw import dlt, pqc
from pqfw.ledger import FixedClock, build_receipt, codeword_commitment, sign_receipt


def _validators(n: int = 3):
    return [pqc.sig_keypair() for _ in range(n)]


def _network(n: int = 3, k: int = 2) -> dlt.LedgerNetwork:
    return dlt.LedgerNetwork(_validators(n), quorum=k, clock=FixedClock())


def _receipt(rid: str, n: int = 0):
    sig_pk, sig_sk = pqc.sig_keypair()
    record = build_receipt(
        doc_id="doc-1",
        recipient_id=rid,
        session_id=f"{rid}#0",
        recipient_sig_pk=sig_pk,
        doc_hash=pqc.sha3_hex(f"copy-{rid}-{n}".encode()),
        commitment=codeword_commitment([1, 0, 1, 1, 0], salt=bytes([n]) * 16),
        clock=FixedClock(),
        nonce=bytes([n]) * 16,
    )
    return record, sign_receipt(record, sig_sk), sig_pk


def _populate(network: dlt.LedgerNetwork, count: int = 4):
    for i in range(count):
        record, sig, pk = _receipt(f"r{i:02d}", n=i)
        network.submit(record, sig, pk)
    return network


# ---------------------------------------------------------------------------
# replication
# ---------------------------------------------------------------------------


def test_every_validator_holds_its_own_complete_replica() -> None:
    network = _populate(_network())
    assert len({len(n.ledger.entries) for n in network.nodes}) == 1
    assert all(len(n.ledger.entries) == 4 for n in network.nodes)
    assert len({n.head for n in network.nodes}) == 1, "honest nodes agree on the head"


def test_each_validator_verifies_independently_rather_than_trusting_the_submitter() -> None:
    """A node that signed whatever it was handed would add a signature and no security."""
    network = _network()
    record, sig, pk = _receipt("r00")
    forged = bytearray(sig)
    forged[7] ^= 0xFF

    with pytest.raises(ValueError, match="validators accepted"):
        network.submit(record, bytes(forged), pk)
    assert all(n.ledger.entries == [] for n in network.nodes)


def test_a_block_commits_only_at_quorum() -> None:
    network = _populate(_network(n=3, k=2))
    block = network.seal_block()
    assert block is not None
    assert network.count_votes(block) >= 2
    assert all(n.height == 1 for n in network.nodes)
    assert block.prev_block_hash == dlt.GENESIS_HASH
    assert block.from_seq == 0 and block.to_seq == 3


def test_blocks_chain_to_each_other() -> None:
    network = _populate(_network(), count=2)
    first = network.seal_block()
    assert first is not None
    assert network.seal_block() is None, "nothing new to seal"

    record, sig, pk = _receipt("r09", n=9)
    network.submit(record, sig, pk)
    second = network.seal_block()

    assert second is not None
    assert second.height == 1
    assert second.prev_block_hash == first.block_hash()
    assert second.from_seq == first.to_seq + 1


def test_a_validator_refuses_to_sign_a_block_it_cannot_reproduce() -> None:
    """The mechanism that makes replication worth anything: an honest node endorses only
    what its own entries produce, so a rewritten history collects no honest signatures."""
    import dataclasses

    network = _populate(_network())
    proposal = network.nodes[0].propose("2026-01-01T00:00:00+00:00")
    assert proposal is not None

    forged = dataclasses.replace(
        proposal, merkle_root=pqc.sha3_hex(b"a more convenient history")
    )
    assert all(node.vote(forged) is None for node in network.nodes)


# ---------------------------------------------------------------------------
# the requirement: one compromised administrator changes nothing
# ---------------------------------------------------------------------------


def test_compromising_one_validator_is_detected_and_out_voted() -> None:
    network = _populate(_network(n=3, k=2))
    network.seal_block()
    assert network.consensus().ok is True

    damage = network.corrupt_node(1, seq=0)
    assert damage["before"] is not None

    report = network.consensus()
    assert report.diverged == [1], "the tampered replica must stand out"
    assert report.agreeing == [0, 2]
    assert report.honest_majority is True, "the honest nodes still make quorum"
    assert report.ok is False
    assert any("validator 1" in p for p in report.problems)

    # and reads go to the honest majority, not to whichever node answered first
    canonical = network.canonical_ledger()
    assert canonical.verify_chain().ok is True
    assert canonical is not network.nodes[1].ledger


def test_a_compromised_validator_cannot_get_its_rewrite_committed() -> None:
    network = _populate(_network(n=3, k=2))
    network.seal_block()
    network.corrupt_node(0, seq=1)

    record, sig, pk = _receipt("r77", n=7)
    network.submit(record, sig, pk)

    # node 0 proposes from its rewritten replica; the honest nodes will not endorse it
    poisoned = network.nodes[0].propose("2026-01-01T00:00:05+00:00")
    assert poisoned is not None
    honest_votes = [network.nodes[i].vote(poisoned) for i in (1, 2)]
    assert all(v is None for v in honest_votes)


def test_rewriting_history_needs_a_whole_quorum_not_one_account() -> None:
    """Corrupt one of three: out-voted. Corrupt two of three: the network can no longer
    be trusted, and says so rather than quietly agreeing."""
    network = _populate(_network(n=3, k=2))
    network.seal_block()

    network.corrupt_node(0, seq=0)
    assert network.consensus().honest_majority is True

    network.corrupt_node(1, seq=0)
    report = network.consensus()
    assert report.honest_majority is False
    assert report.ok is False


# ---------------------------------------------------------------------------
# lookups and proofs
# ---------------------------------------------------------------------------


def test_find_by_commitment_reads_the_honest_chain() -> None:
    network = _populate(_network())
    network.seal_block()
    wanted = network.nodes[0].ledger.entries[2].record["codeword_commitment"]

    network.corrupt_node(0, seq=2)
    found = network.find_by_commitment(wanted)
    assert found is not None and found.seq == 2
    assert found.signature_is_valid() is True


def test_inclusion_proof_ties_a_receipt_to_a_quorum_signed_block() -> None:
    network = _populate(_network())
    network.seal_block()

    for seq in range(4):
        block, proof = network.inclusion_proof(seq)
        entry = network.canonical_ledger().entries[seq]
        assert network.verify_inclusion(entry.entry_hash, proof, block) is True
        assert network.count_votes(block) >= network.quorum

    forged = pqc.sha3_hex(b"a receipt nobody signed")
    block, proof = network.inclusion_proof(0)
    assert network.verify_inclusion(forged, proof, block) is False


def test_an_unsealed_receipt_has_no_inclusion_proof_yet() -> None:
    network = _populate(_network())
    with pytest.raises(KeyError, match="not in a committed block"):
        network.inclusion_proof(0)


# ---------------------------------------------------------------------------
# persistence and configuration
# ---------------------------------------------------------------------------


def test_the_network_survives_a_restart(tmp_path) -> None:
    keys = _validators()
    network = dlt.LedgerNetwork(keys, quorum=2, clock=FixedClock())
    _populate(network)
    network.seal_block()
    network.save(tmp_path / "dlt")

    reloaded = dlt.LedgerNetwork(keys, quorum=2, clock=FixedClock()).load(tmp_path / "dlt")
    assert [len(n.ledger.entries) for n in reloaded.nodes] == [4, 4, 4]
    assert reloaded.consensus().ok is True
    assert reloaded.nodes[0].blocks[0].block_hash() == network.nodes[0].blocks[0].block_hash()


def test_an_unsatisfiable_quorum_is_refused() -> None:
    with pytest.raises(ValueError, match="not satisfiable"):
        dlt.LedgerNetwork(_validators(3), quorum=4)
    with pytest.raises(ValueError, match="at least one validator"):
        dlt.LedgerNetwork([], quorum=1)


def test_votes_from_unrecognised_keys_do_not_count() -> None:
    """An attacker who spins up their own validators gains nothing."""
    import dataclasses

    network = _populate(_network())
    block = network.seal_block()
    assert block is not None

    impostors = _validators(4)
    body = pqc.canonical(block.header())
    fake_votes = [pqc.sig_sign(body, sk).hex() for _pk, sk in impostors]
    padded = dataclasses.replace(block, votes=fake_votes)
    assert network.count_votes(padded) == 0
