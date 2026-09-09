"""Tracing: leaked bytes in, an accusation with a stated error probability out.

The report this produces is the deliverable of the whole project, so it is built to be
argued with. It carries the p-value, the number of slots that were actually readable,
the runners-up, and the three independent verification results -- and it refuses to
call itself conclusive unless every one of them holds.

The four conditions for ``conclusive``
--------------------------------------
1. The corrected p-value clears alpha.  Statistical evidence.
2. The named recipient's ML-DSA-65 receipt verifies.  They admitted holding this copy.
3. The ledger chain is intact.  That receipt has not been edited or inserted.
4. A k-of-n witness checkpoint covers it.  Nor has the whole ledger been rewritten.

Statistics alone gives you a suspect, not a case. Condition 1 says the marks in this
file match a codeword; conditions 2 to 4 say the codeword was issued to a person who
signed for it, and that the record of that has not been touched since. Dropping any of
them turns a traceable release into an assertion by whoever runs the software.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from pqfw import tardos
from pqfw.carrier import get_carrier
from pqfw.ledger import Ledger, codeword_commitment, verify_merkle_proof
from pqfw.store import Store
from pqfw.tardos import Accusation


@dataclass(frozen=True)
class Suspect:
    recipient_id: str
    accusation: Accusation

    def to_json(self) -> dict[str, Any]:
        return {"recipient_id": self.recipient_id, **self.accusation.to_json()}


@dataclass(frozen=True)
class TraceReport:
    doc_id: str
    carrier: str
    alpha: float

    m: int
    m_eff: int
    """Readable slots. The evidence is exactly as strong as this is large."""

    accused: Suspect | None
    runners_up: list[Suspect] = field(default_factory=list)

    ledger_seq: int | None = None
    receipt_signature_valid: bool = False
    chain_ok: bool = False
    chain_problems: list[str] = field(default_factory=list)
    checkpoint_index: int | None = None
    checkpoint_witnesses: int = 0
    checkpoint_required: int = 0
    checkpoint_valid: bool = False
    inclusion_proof_valid: bool = False

    notes: list[str] = field(default_factory=list)

    @property
    def statistically_significant(self) -> bool:
        """Gated on the provable Chernoff bound, not the Gaussian approximation.

        The Gaussian p-value is reported alongside for comparison, but it understates
        the tail at these code lengths (see tardos.chernoff_log10_bound), and an
        accusation may not rest on an optimistic number.
        """
        return self.accused is not None and self.accused.accusation.p_bound < self.alpha

    @property
    def conclusive(self) -> bool:
        """All four conditions, or it is not a positive identification.

        A trace that clears the statistics but cannot produce a verified, chained,
        checkpointed receipt is a lead. Reporting it as an identification is how an
        innocent person gets named.
        """
        return (
            self.statistically_significant
            and self.receipt_signature_valid
            and self.chain_ok
            and self.checkpoint_valid
            and self.inclusion_proof_valid
        )

    @property
    def verdict(self) -> str:
        if self.conclusive:
            return "IDENTIFIED"
        if self.statistically_significant:
            return "UNCORROBORATED"
        return "NO IDENTIFICATION"

    def to_json(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "carrier": self.carrier,
            "alpha": self.alpha,
            "verdict": self.verdict,
            "conclusive": self.conclusive,
            "statistically_significant": self.statistically_significant,
            "m": self.m,
            "m_eff": self.m_eff,
            "accused": self.accused.to_json() if self.accused else None,
            "runners_up": [s.to_json() for s in self.runners_up],
            "ledger": {
                "seq": self.ledger_seq,
                "receipt_signature_valid": self.receipt_signature_valid,
                "chain_ok": self.chain_ok,
                "chain_problems": self.chain_problems,
                "checkpoint_index": self.checkpoint_index,
                "checkpoint_witnesses": self.checkpoint_witnesses,
                "checkpoint_required": self.checkpoint_required,
                "checkpoint_valid": self.checkpoint_valid,
                "inclusion_proof_valid": self.inclusion_proof_valid,
            },
            "notes": self.notes,
        }


def extract_bits(leaked: bytes, doc_id: str, store: Store) -> list[int | None]:
    record = store.doc(doc_id)
    carrier = get_carrier(record.carrier)
    return carrier.extract(leaked, record.locators)


def trace(
    leaked: bytes,
    doc_id: str,
    store: Store,
    ledger: Ledger | None = None,
    alpha: float = 1e-6,
    runners_up: int = 4,
) -> TraceReport:
    record = store.doc(doc_id)
    ledger = ledger if ledger is not None else store.ledger()
    notes: list[str] = []

    # 1-3. extract, score, rank
    y = extract_bits(leaked, doc_id, store)
    ranked = tardos.rank(record.code(), y)
    m_eff = tardos.readable_count(y, record.params.m)
    if m_eff < record.params.m:
        notes.append(
            f"{record.params.m - m_eff} of {record.params.m} slots were unreadable and "
            f"scored as erasures, not as zeros"
        )

    def as_suspect(a: Accusation) -> Suspect:
        index = a.recipient_index
        rid = (
            record.recipient_order[index]
            if index < len(record.recipient_order)
            else f"<unissued codeword {index}>"
        )
        return Suspect(recipient_id=rid, accusation=a)

    issued = [a for a in ranked if a.recipient_index < len(record.recipient_order)]
    top = as_suspect(issued[0]) if issued else None
    others = [as_suspect(a) for a in issued[1 : 1 + runners_up]]

    report_kwargs: dict[str, Any] = {
        "doc_id": doc_id,
        "carrier": record.carrier,
        "alpha": alpha,
        "m": record.params.m,
        "m_eff": m_eff,
        "accused": top,
        "runners_up": others,
        "notes": notes,
    }

    chain = ledger.verify_chain()
    report_kwargs["chain_ok"] = chain.ok
    report_kwargs["chain_problems"] = chain.problems
    report_kwargs["checkpoint_required"] = store.state.witness_threshold

    if top is None or top.accusation.p_bound >= alpha:
        notes.append(
            "no recipient clears the significance threshold; the ledger checks below "
            "are reported for completeness but identify nobody"
        )
        return TraceReport(**report_kwargs)

    # 4. find the receipt by recommitting to the accused recipient's codeword
    rid = top.recipient_id
    salt_hex = record.salts.get(rid)
    if salt_hex is None:
        notes.append(f"no commitment salt stored for {rid}: cannot locate a receipt")
        return TraceReport(**report_kwargs)

    commitment = codeword_commitment(
        record.X[record.index_of(rid)], bytes.fromhex(salt_hex)
    )
    entry = ledger.find_by_commitment(commitment)
    if entry is None:
        notes.append(
            f"{rid} matches the marks in this copy but never signed a decryption "
            f"receipt for it: no ledger entry carries their commitment"
        )
        return TraceReport(**report_kwargs)

    # 5. verify the receipt, the chain, and the checkpoint over it
    report_kwargs["ledger_seq"] = entry.seq
    report_kwargs["receipt_signature_valid"] = entry.signature_is_valid()

    witness_pks = store.witness_public_keys()
    threshold = store.state.witness_threshold
    try:
        checkpoint, proof = ledger.inclusion_proof(entry.seq)
    except KeyError:
        notes.append(
            f"ledger entry {entry.seq} is not covered by a witness checkpoint yet; "
            f"run 'pqfw audit --checkpoint' before relying on this trace"
        )
        return TraceReport(**report_kwargs)

    report_kwargs["checkpoint_index"] = checkpoint.index
    report_kwargs["checkpoint_witnesses"] = Ledger.count_witnesses(checkpoint, witness_pks)
    report_kwargs["checkpoint_valid"] = (
        report_kwargs["checkpoint_witnesses"] >= threshold and threshold >= 1
    )
    report_kwargs["inclusion_proof_valid"] = verify_merkle_proof(
        entry.entry_hash, proof, checkpoint.root
    )

    return TraceReport(**report_kwargs)


def trace_bits(
    y: Sequence[int | None],
    doc_id: str,
    store: Store,
    alpha: float = 1e-6,
) -> list[Suspect]:
    """Score a bit vector that was extracted elsewhere.

    Used by the evaluation harness, which forges y directly rather than assembling
    tens of thousands of documents. Never used on the evidence path: a real trace
    starts from the leaked bytes.
    """
    record = store.doc(doc_id)
    return [
        Suspect(recipient_id=record.recipient_order[a.recipient_index], accusation=a)
        for a in tardos.rank(record.code(), y)
        if a.recipient_index < len(record.recipient_order)
    ]
