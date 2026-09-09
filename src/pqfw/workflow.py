"""The five operations, as functions.

The CLI and the web demo are both thin shells over this module. Keeping the workflow
here rather than in cli.py means the end-to-end tests exercise the same code path a
demo does, instead of a parallel one that can drift.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import numpy as np

from pqfw import ledger as L
from pqfw import package as pkg
from pqfw import pqc, tardos
from pqfw.carrier import get_carrier
from pqfw.carriers import pdf as _pdf_carrier  # noqa: F401  -- registers the carrier
from pqfw.carriers import text as _text_carrier  # noqa: F401  -- registers the carrier
from pqfw.store import DocRecord, Store
from pqfw.trace import TraceReport, trace

DEFAULT_WITNESSES = 3
DEFAULT_THRESHOLD = 2
DEFAULT_SESSIONS = 3
"""Decryption credentials pre-issued per recipient.

Each one carries its own Tardos codeword, so each decryption yields a distinct
fingerprint and a distinct ledger commitment.
"""


@dataclass(frozen=True)
class ProtectResult:
    doc_id: str
    m: int
    m_requested: int
    capacity: int
    capped: bool
    recipients: int
    sessions: int
    """Total decryption credentials issued: one codeword and one wrapped bundle each."""
    sessions_per_recipient: int
    package_path: str
    size: dict[str, int]
    achievable_eps: float
    """Best false-accusation probability the achieved code length can be expected to
    reach against a single leaker. When the carrier caps the code, this is the number
    that is actually on offer rather than the one that was asked for."""

    def to_json(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "slots": self.m,
            "slots_requested": self.m_requested,
            "carrier_capacity": self.capacity,
            "capped_by_carrier": self.capped,
            "recipients": self.recipients,
            "sessions": self.sessions,
            "sessions_per_recipient": self.sessions_per_recipient,
            "package": self.package_path,
            "size": self.size,
            "achievable_eps": self.achievable_eps,
        }


@dataclass(frozen=True)
class OpenResult:
    doc_id: str
    recipient_id: str
    session_id: str
    """Which of the recipient's decryption credentials this copy came from."""
    sessions_left: int
    document: bytes
    doc_hash: str
    ledger_seq: int
    entry_hash: str


# ---------------------------------------------------------------------------


def enroll(
    store: Store,
    recipients: int,
    witnesses: int = DEFAULT_WITNESSES,
    threshold: int = DEFAULT_THRESHOLD,
    prefix: str = "r",
) -> dict[str, Any]:
    """Create recipient keypairs and the witness set."""
    store.init()
    ids = [f"{prefix}{i:02d}" for i in range(recipients)]
    for rid in ids:
        store.enroll_recipient(rid)
    fingerprints = store.enroll_witnesses(witnesses, threshold)
    store.save()
    return {
        "recipients": ids,
        "witnesses": fingerprints,
        "threshold": threshold,
        "algorithms": pqc.alg_report(),
    }


def protect(
    store: Store,
    source: bytes,
    doc_id: str,
    carrier_name: str = "text-zwsp",
    coalition: int = 3,
    eps1: float = 1e-6,
    constant: float = 100.0,
    slots: int | None = None,
    sessions_per_recipient: int = DEFAULT_SESSIONS,
    rng: np.random.Generator | None = None,
) -> ProtectResult:
    """Encrypt once, for every enrolled recipient, with a distinct fingerprint each.

    The Tardos code length is what the target coalition size and error probability ask
    for, capped by however many slots the document can actually hold. When the cap
    bites we say so and carry on: the accusation's p-value is computed from the score
    that was observed, so a short code produces weaker evidence rather than false
    evidence.
    """
    rng = rng if rng is not None else np.random.default_rng()
    recipient_ids = store.recipient_ids()
    if not recipient_ids:
        raise ValueError("no recipients enrolled; run enroll first")

    carrier = get_carrier(carrier_name)
    capacity = carrier.capacity(source)
    wanted = slots if slots is not None else tardos.code_length(coalition, eps1, constant)
    m = min(wanted, capacity)
    if m < 1:
        raise ValueError(f"the {carrier_name} carrier found no usable slots in this document")

    # One codeword, and one wrapped bundle, per *decryption session* rather than per
    # recipient. A person who opens the document twice must not receive the same bytes
    # twice: identical copies make a leak attributable to the person but not to the
    # decryption event, and the spec asks for the event.
    #
    # The credentials are pre-issued here rather than minted on demand, so a recipient
    # can decrypt with the distributor unreachable -- which is what an air-gapped
    # deployment means. The pool is finite by design; running out is a reissue, and a
    # reissue is itself an act somebody has to perform.
    session_ids: list[str] = []
    session_owner: dict[str, str] = {}
    for rid in recipient_ids:
        for s in range(sessions_per_recipient):
            session_id = f"{rid}#{s}"
            session_ids.append(session_id)
            session_owner[session_id] = rid

    code = tardos.generate(
        tardos.TardosParams(m=m, n=len(session_ids), c=coalition, eps1=eps1), rng
    )
    plan = carrier.plan(source, m, rng)

    # One Recipient entry per session, sharing the owner's keys. The envelope's AAD
    # therefore binds to the session id, so an envelope cannot be replayed from one
    # session onto another even by the person who holds both.
    recipients = [
        pkg.Recipient(
            recipient_id=session_id,
            kem_pk=_b64d(store.recipient_public(session_owner[session_id])["kem_pk"]),
            sig_pk=_b64d(store.recipient_public(session_owner[session_id])["sig_pk"]),
        )
        for session_id in session_ids
    ]
    package = pkg.build_package(doc_id, plan, code, recipients)

    salts = {sid: os.urandom(16).hex() for sid in session_ids}
    commitments = {
        sid: L.codeword_commitment(code.X[j], bytes.fromhex(salts[sid]))
        for j, sid in enumerate(session_ids)
    }

    store.put_doc(
        DocRecord(
            doc_id=doc_id,
            carrier=carrier_name,
            created_at=store.clock.now(),
            source_hash=pqc.sha3_hex(source),
            locators=plan.locators(),
            params=code.params,
            p=code.p,
            X=code.X,
            session_order=session_ids,
            session_owner=session_owner,
            salts=salts,
            commitments=commitments,
        )
    )
    store.package_path(doc_id).parent.mkdir(parents=True, exist_ok=True)
    package.save(store.package_path(doc_id))
    store.save()

    return ProtectResult(
        doc_id=doc_id,
        m=m,
        m_requested=wanted,
        capacity=capacity,
        capped=m < wanted,
        recipients=len(recipient_ids),
        sessions=len(session_ids),
        sessions_per_recipient=sessions_per_recipient,
        package_path=str(store.package_path(doc_id)),
        size=package.size_report(),
        achievable_eps=tardos.achievable_eps(code),
    )


def open_as(store: Store, doc_id: str, recipient_id: str) -> OpenResult:
    """Decrypt as one recipient and append their signed receipt to the ledger.

    Signing happens on the recipient's side, with the recipient's key: the distributor
    could not produce this receipt on their behalf, which is what makes an entry
    evidence rather than a claim.
    """
    record = store.doc(doc_id)
    package = pkg.DistributionPackage.load(store.package_path(doc_id))
    device = store.recipient_device(recipient_id)

    session_id = record.next_free_session(recipient_id)
    if session_id is None:
        raise ValueError(
            f"{recipient_id} has spent all "
            f"{len(record.sessions_for(recipient_id))} decryption credentials for "
            f"{doc_id!r}; the distributor must issue more"
        )

    opened = pkg.open_package(package, session_id, device["kem_sk"])

    ledger = store.ledger()
    receipt = L.build_receipt(
        doc_id=doc_id,
        recipient_id=recipient_id,
        session_id=session_id,
        recipient_sig_pk=device["sig_pk"],
        doc_hash=opened.doc_hash,
        commitment=record.commitments[session_id],
        clock=store.clock,
    )
    signature = L.sign_receipt(receipt, device["sig_sk"])
    entry_hash = ledger.append(receipt, signature, device["sig_pk"])
    store.save_ledger(ledger)

    # ... and to the replicated ledger, where a quorum of validators must each
    # independently verify the recipient's signature before the receipt counts as
    # recorded at all.
    network = store.network()
    network.submit(receipt, signature, device["sig_pk"])
    store.save_network(network)

    record.consumed[session_id] = store.clock.now()
    store.save()

    return OpenResult(
        doc_id=doc_id,
        recipient_id=recipient_id,
        session_id=session_id,
        sessions_left=len(
            [s for s in record.sessions_for(recipient_id) if s not in record.consumed]
        ),
        document=opened.document,
        doc_hash=opened.doc_hash,
        ledger_seq=ledger.entries[-1].seq,
        entry_hash=entry_hash,
    )


def checkpoint(store: Store, k: int | None = None) -> L.Checkpoint | None:
    """Seal a block on the validator network, and cut the matching local checkpoint."""
    network = store.network()
    if network.seal_block() is not None:
        store.save_network(network)

    ledger = store.ledger()
    threshold = k if k is not None else store.state.witness_threshold
    secret_keys = store.witness_secret_keys()
    if not secret_keys:
        raise ValueError("no witnesses enrolled; run enroll first")
    try:
        cp = ledger.checkpoint(secret_keys, threshold)
    except ValueError:
        return None
    store.save_ledger(ledger)
    return cp


def trace_leak(
    store: Store, doc_id: str, leaked: bytes, alpha: float = 1e-6
) -> TraceReport:
    return trace(leaked, doc_id, store, ledger=store.ledger(), alpha=alpha)


def audit(store: Store) -> dict[str, Any]:
    ledger = store.ledger()
    chain = ledger.verify_chain()
    witness_pks = store.witness_public_keys()
    threshold = store.state.witness_threshold

    checkpoints = []
    for cp in ledger.checkpoints:
        witnesses = L.Ledger.count_witnesses(cp, witness_pks)
        covered = [e for e in ledger.entries if cp.from_seq <= e.seq <= cp.to_seq]
        # Recompute from the entries' *contents*, not their stored hashes. A stored
        # hash that has gone stale is caught by the chain check; entries removed from
        # the end are not, and this is what sees them: the signed root still covers
        # them and the recomputed root no longer can.
        expected_count = cp.to_seq - cp.from_seq + 1
        recomputed = L.merkle_root([e.compute_hash() for e in covered])
        checkpoints.append(
            {
                "index": cp.index,
                "range": [cp.from_seq, cp.to_seq],
                "root": cp.root,
                "at": cp.at,
                "witnesses": witnesses,
                "valid": witnesses >= threshold,
                "covers_entries": len(covered),
                "covers_expected": expected_count,
                "root_matches_entries": len(covered) == expected_count
                and recomputed == cp.root,
                "anchor": L.checkpoint_anchor(cp),
            }
        )

    try:
        consensus = store.network().consensus().to_json()
    except ValueError:
        consensus = None

    return {
        "entries": chain.entries,
        "chain": chain.to_json(),
        "consensus": consensus,
        "witness_threshold": threshold,
        "witnesses_enrolled": len(witness_pks),
        "checkpoints": checkpoints,
        # Two different questions, deliberately not merged. "ok" is "nothing is wrong
        # anywhere", which a single diverged replica makes false. "honest_majority",
        # reported inside consensus, is "the network still functions" -- and it stays
        # true through exactly the attack the requirement names. A compromised
        # validator should show up as degraded, not as fine, and not as fatal either.
        "ok": (
            chain.ok
            and all(c["valid"] and c["root_matches_entries"] for c in checkpoints)
            and (consensus is None or consensus["ok"])
        ),
        "algorithms": pqc.alg_report(),
    }


def tamper(store: Store, seq: int, field: str = "doc_hash") -> dict[str, Any]:
    """Deliberately corrupt one ledger entry so detection can be shown live.

    Present because a demo of tamper evidence that never tampers is not a demo. It
    edits the stored ledger in place -- exactly what a dishonest administrator would
    do -- and leaves it broken until the operator restores it.
    """
    ledger = store.ledger()
    if not 0 <= seq < len(ledger.entries):
        raise IndexError(f"no ledger entry {seq}; the ledger holds {len(ledger.entries)}")

    backup = store.ledger_path.with_suffix(".json.pristine")
    if not backup.exists():
        backup.write_bytes(store.ledger_path.read_bytes())

    before = ledger.entries[seq].record.get(field)
    ledger.entries[seq].record[field] = pqc.sha3_hex(f"tampered:{before}".encode())
    store.save_ledger(ledger)
    return {
        "seq": seq,
        "field": field,
        "before": before,
        "after": ledger.entries[seq].record[field],
        "backup": str(backup),
    }


def compromise_validator(store: Store, node: int, seq: int = 0) -> dict[str, Any]:
    """Take over one validator and rewrite a receipt inside its replica only.

    This is the attack the requirement names by name -- a single administrator, or a
    single compromised account. Running it is the point: the node's state root moves,
    it stops agreeing with the others, its own chain check fails because it cannot
    forge the recipient's ML-DSA-65 signature, and the remaining validators still make
    quorum without it.
    """
    network = store.network()
    if not 0 <= node < len(network.nodes):
        raise IndexError(f"there are {len(network.nodes)} validators; no node {node}")
    damage = network.corrupt_node(node, seq)
    store.save_network(network)
    return {**damage, "consensus": network.consensus().to_json()}


def heal_validators(store: Store) -> dict[str, Any]:
    """Re-sync a compromised replica from the honest majority.

    Recovery, not repair: the tampered entries cannot be mended, because nobody but the
    recipient can re-sign them. The node is simply given the chain the honest quorum
    holds, which is what a real operator would do after evicting an intruder.
    """
    import copy as _copy

    network = store.network()
    report = network.consensus()
    trusted = sorted(set(report.agreeing) & set(report.valid))
    if not trusted:
        return {"healed": [], "reason": "no trusted replica to re-sync from"}

    source = network.nodes[trusted[0]]
    healed = []
    for node in network.nodes:
        if node.index in trusted:
            continue
        node.ledger = _copy.deepcopy(source.ledger)
        node.blocks = list(source.blocks)
        healed.append(node.index)
    store.save_network(network)
    return {"healed": healed, "consensus": network.consensus().to_json()}


def restore(store: Store) -> bool:
    """Put back the pre-tamper ledger, so the demo can be run twice.

    Only ever restores a copy this process took before corrupting the file. There is
    no way to repair a genuinely tampered ledger: the recipient signatures cannot be
    reproduced without the recipients' keys, which is the entire point.
    """
    backup = store.ledger_path.with_suffix(".json.pristine")
    if not backup.exists():
        return False
    store.ledger_path.write_bytes(backup.read_bytes())
    backup.unlink()
    return True


def _b64d(text: str) -> bytes:
    import base64

    return base64.b64decode(text.encode("ascii"))
