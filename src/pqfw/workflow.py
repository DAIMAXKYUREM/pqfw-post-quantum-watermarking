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
from pqfw.carriers import text as _text_carrier  # noqa: F401  -- registers the carrier
from pqfw.store import DocRecord, Store
from pqfw.trace import TraceReport, trace

DEFAULT_WITNESSES = 3
DEFAULT_THRESHOLD = 2


@dataclass(frozen=True)
class ProtectResult:
    doc_id: str
    m: int
    m_requested: int
    capacity: int
    capped: bool
    recipients: int
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
            "package": self.package_path,
            "size": self.size,
            "achievable_eps": self.achievable_eps,
        }


@dataclass(frozen=True)
class OpenResult:
    doc_id: str
    recipient_id: str
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

    code = tardos.generate(
        tardos.TardosParams(m=m, n=len(recipient_ids), c=coalition, eps1=eps1), rng
    )
    plan = carrier.plan(source, m, rng)

    recipients = [
        pkg.Recipient(
            recipient_id=rid,
            kem_pk=_b64d(store.recipient_public(rid)["kem_pk"]),
            sig_pk=_b64d(store.recipient_public(rid)["sig_pk"]),
        )
        for rid in recipient_ids
    ]
    package = pkg.build_package(doc_id, plan, code, recipients)

    salts = {rid: os.urandom(16).hex() for rid in recipient_ids}
    commitments = {
        rid: L.codeword_commitment(code.X[j], bytes.fromhex(salts[rid]))
        for j, rid in enumerate(recipient_ids)
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
            recipient_order=recipient_ids,
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

    opened = pkg.open_package(package, recipient_id, device["kem_sk"])

    ledger = store.ledger()
    receipt = L.build_receipt(
        doc_id=doc_id,
        recipient_id=recipient_id,
        recipient_sig_pk=device["sig_pk"],
        doc_hash=opened.doc_hash,
        commitment=record.commitments[recipient_id],
        clock=store.clock,
    )
    signature = L.sign_receipt(receipt, device["sig_sk"])
    entry_hash = ledger.append(receipt, signature, device["sig_pk"])
    store.save_ledger(ledger)

    return OpenResult(
        doc_id=doc_id,
        recipient_id=recipient_id,
        document=opened.document,
        doc_hash=opened.doc_hash,
        ledger_seq=ledger.entries[-1].seq,
        entry_hash=entry_hash,
    )


def checkpoint(store: Store, k: int | None = None) -> L.Checkpoint | None:
    """Cut a witness-signed checkpoint over everything appended since the last one."""
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

    return {
        "entries": chain.entries,
        "chain": chain.to_json(),
        "witness_threshold": threshold,
        "witnesses_enrolled": len(witness_pks),
        "checkpoints": checkpoints,
        "ok": chain.ok and all(c["valid"] and c["root_matches_entries"] for c in checkpoints),
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
