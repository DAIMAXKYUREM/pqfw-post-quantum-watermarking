"""Append-only, hash-chained, witness-checkpointed decryption ledger.

Every time a recipient opens a package they sign a *decryption receipt* with
ML-DSA-65 and it is appended here. The chain gives ordering and tamper evidence; the
k-of-n witness signatures over Merkle checkpoints remove the single administrator who
could otherwise rewrite history and re-sign it.

What the ledger deliberately does not contain
---------------------------------------------
Not the codeword. Not the slot locators. Not the biases. A receipt carries
SHA3-256(codeword || salt) and nothing else about the fingerprint, so the ledger can
be published in full -- handed to every recipient, pinned in a newspaper, printed as
a QR code and stuck on a wall -- without giving anybody the means to forge, strip or
transplant a mark. The distributor's sealed store holds the pre-images.

Why the witnesses matter
------------------------
A hash chain alone only proves that *whoever holds the chain* has not edited the
middle of it. An administrator who can rewrite the whole file can recompute every
hash. Checkpoint roots signed by k of n independent witness keys make that useless:
the administrator would also have to forge k signatures over the rewritten root, and
the witness keys are not theirs. Exporting the root as a QR code is the air-gapped
anchor -- print it, and the paper is now a witness too.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol, Sequence

from pqfw import pqc

GENESIS_HASH = "0" * 64
CHECKPOINT_LABEL = "pqfw/checkpoint/v1"


# ---------------------------------------------------------------------------
# clock injection
# ---------------------------------------------------------------------------


class Clock(Protocol):
    def now(self) -> str:
        """ISO-8601 UTC timestamp."""
        ...


class SystemClock:
    def now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class FixedClock:
    """Deterministic clock for tests and for the evaluation harness.

    No library code in PQFW calls datetime.now() directly; a clock is always passed
    in. A ledger whose contents depend on wall time cannot be regression tested.
    """

    start: str = "2026-01-01T00:00:00+00:00"
    step_seconds: int = 1
    _tick: int = 0

    def now(self) -> str:
        from datetime import timedelta

        base = datetime.fromisoformat(self.start)
        out = base + timedelta(seconds=self.step_seconds * self._tick)
        self._tick += 1
        return out.isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# receipts
# ---------------------------------------------------------------------------


def codeword_commitment(codeword: Sequence[int], salt: bytes) -> str:
    """SHA3-256(codeword_bytes || salt).

    The salt stops anybody with a candidate codeword -- for instance, a recipient who
    read their own marks out of their own copy -- from confirming a guess about
    somebody else's receipt by recomputing the hash.
    """
    codeword_bytes = bytes(int(b) & 1 for b in codeword)
    return pqc.sha3_hex(codeword_bytes + salt)


def build_receipt(
    doc_id: str,
    recipient_id: str,
    session_id: str,
    recipient_sig_pk: bytes,
    doc_hash: str,
    commitment: str,
    clock: Clock,
    nonce: bytes | None = None,
) -> dict[str, str]:
    """The object the recipient signs. Canonical JSON is what actually gets signed.

    ``session_id`` names the specific decryption, not just the person: two decryptions
    by the same recipient carry different codewords and therefore different
    commitments, so a leaked copy resolves to one event rather than to a set of them.
    """
    return {
        "doc_id": doc_id,
        "recipient_id": recipient_id,
        "session_id": session_id,
        "recipient_sig_pk_fpr": pqc.pk_fingerprint(recipient_sig_pk),
        "timestamp": clock.now(),
        "doc_hash": doc_hash,
        "codeword_commitment": commitment,
        "nonce": (nonce or os.urandom(16)).hex(),
    }


def sign_receipt(record: dict[str, Any], sig_sk: bytes) -> bytes:
    return pqc.sig_sign(pqc.canonical(record), sig_sk)


# ---------------------------------------------------------------------------
# entries
# ---------------------------------------------------------------------------


@dataclass
class Entry:
    seq: int
    prev_hash: str
    record: dict[str, Any]
    recipient_sig: str
    """hex ML-DSA-65 signature over canonical(record)."""
    recipient_sig_pk: str
    """base64 ML-DSA-65 public key. Carried in the entry so the ledger verifies
    standalone, without the enrollment database next to it."""
    entry_hash: str = ""

    def body(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "record": self.record,
            "recipient_sig": self.recipient_sig,
            "recipient_sig_pk": self.recipient_sig_pk,
        }

    def compute_hash(self) -> str:
        return pqc.canonical_hash(self.body())

    def signature_is_valid(self) -> bool:
        import base64

        try:
            pk = base64.b64decode(self.recipient_sig_pk)
            sig = bytes.fromhex(self.recipient_sig)
        except Exception:
            return False
        if pqc.pk_fingerprint(pk) != self.record.get("recipient_sig_pk_fpr"):
            return False
        return pqc.sig_verify(pqc.canonical(self.record), sig, pk)

    def to_json(self) -> dict[str, Any]:
        return {**self.body(), "entry_hash": self.entry_hash}

    @staticmethod
    def from_json(obj: dict[str, Any]) -> "Entry":
        return Entry(
            seq=int(obj["seq"]),
            prev_hash=obj["prev_hash"],
            record=obj["record"],
            recipient_sig=obj["recipient_sig"],
            recipient_sig_pk=obj["recipient_sig_pk"],
            entry_hash=obj.get("entry_hash", ""),
        )


@dataclass(frozen=True)
class ChainReport:
    ok: bool
    entries: int
    first_bad_seq: int | None
    problems: list[str]

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": self.entries,
            "first_bad_seq": self.first_bad_seq,
            "problems": self.problems,
        }


@dataclass(frozen=True)
class Checkpoint:
    index: int
    from_seq: int
    to_seq: int
    root: str
    at: str
    prev_root: str
    witness_sigs: list[str] = field(default_factory=list)
    """Hex ML-DSA-65 signatures over canonical(signed_body()), unlabelled.

    Deliberately not tagged with which witness produced which signature. An ML-DSA
    secret key does not contain t1, so a public key cannot be recovered from it and
    liboqs offers no derive-public call -- but more usefully, a verifier holding the n
    witness public keys can simply try each key against each signature and count the
    keys that match. That is the real k-of-n question, and it keeps the checkpoint from
    disclosing which witnesses were available at signing time.
    """

    def signed_body(self) -> dict[str, Any]:
        return {
            "label": CHECKPOINT_LABEL,
            "index": self.index,
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "root": self.root,
            "at": self.at,
            "prev_root": self.prev_root,
        }

    def to_json(self) -> dict[str, Any]:
        return {**self.signed_body(), "witness_sigs": self.witness_sigs}

    @staticmethod
    def from_json(obj: dict[str, Any]) -> "Checkpoint":
        return Checkpoint(
            index=int(obj["index"]),
            from_seq=int(obj["from_seq"]),
            to_seq=int(obj["to_seq"]),
            root=obj["root"],
            at=obj["at"],
            prev_root=obj["prev_root"],
            witness_sigs=[str(x) for x in obj.get("witness_sigs", [])],
        )


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------


def _h(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def _leaf(entry_hash: str) -> str:
    return _h(b"\x00" + bytes.fromhex(entry_hash))


def _node(left: str, right: str) -> str:
    return _h(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right))


def merkle_root(entry_hashes: Sequence[str]) -> str:
    """SHA3-256 Merkle root, duplicating the last node on an odd level.

    Leaves and internal nodes are domain separated by a prefix byte so that an
    internal node's digest can never be presented as a leaf -- the second-preimage
    trick that bit early Bitcoin-style trees.
    """
    if not entry_hashes:
        return GENESIS_HASH
    level = [_leaf(x) for x in entry_hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(entry_hashes: Sequence[str], index: int) -> list[dict[str, str]]:
    if not 0 <= index < len(entry_hashes):
        raise IndexError(f"leaf {index} is outside a tree of {len(entry_hashes)}")
    level = [_leaf(x) for x in entry_hashes]
    proof: list[dict[str, str]] = []
    position = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling = position ^ 1
        proof.append({"side": "left" if sibling < position else "right", "hash": level[sibling]})
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        position //= 2
    return proof


def verify_merkle_proof(entry_hash: str, proof: Iterable[dict[str, str]], root: str) -> bool:
    current = _leaf(entry_hash)
    for step in proof:
        current = (
            _node(step["hash"], current)
            if step["side"] == "left"
            else _node(current, step["hash"])
        )
    return current == root


# ---------------------------------------------------------------------------
# the ledger
# ---------------------------------------------------------------------------


class Ledger:
    def __init__(self, clock: Clock | None = None) -> None:
        self.entries: list[Entry] = []
        self.checkpoints: list[Checkpoint] = []
        self.clock: Clock = clock or SystemClock()

    # -- append -------------------------------------------------------------

    def append(self, record: dict[str, Any], recipient_sig: bytes, recipient_sig_pk: bytes) -> str:
        """Append a signed receipt. Returns the new entry's hash.

        An unverified receipt is refused. A ledger that accepts whatever it is handed
        is a log file, not an audit layer: the whole value of the chain is that every
        link was signed by the key named in it.
        """
        import base64

        if pqc.pk_fingerprint(recipient_sig_pk) != record.get("recipient_sig_pk_fpr"):
            raise ValueError(
                "receipt names a different signing key than the one presented with it"
            )
        if not pqc.sig_verify(pqc.canonical(record), recipient_sig, recipient_sig_pk):
            raise ValueError("receipt signature does not verify; refusing to append")

        entry = Entry(
            seq=len(self.entries),
            prev_hash=self.entries[-1].entry_hash if self.entries else GENESIS_HASH,
            record=record,
            recipient_sig=recipient_sig.hex(),
            recipient_sig_pk=base64.b64encode(recipient_sig_pk).decode("ascii"),
        )
        entry.entry_hash = entry.compute_hash()
        self.entries.append(entry)
        return entry.entry_hash

    # -- verify -------------------------------------------------------------

    def verify_chain(self) -> ChainReport:
        """Every link, every sequence number and every signature."""
        problems: list[str] = []
        first_bad: int | None = None

        def fail(seq: int, message: str) -> None:
            nonlocal first_bad
            problems.append(f"seq {seq}: {message}")
            if first_bad is None or seq < first_bad:
                first_bad = seq

        expected_prev = GENESIS_HASH
        for position, entry in enumerate(self.entries):
            if entry.seq != position:
                fail(entry.seq, f"out of order: found at position {position}")
            if entry.prev_hash != expected_prev:
                fail(entry.seq, "prev_hash does not match the preceding entry")
            recomputed = entry.compute_hash()
            if entry.entry_hash != recomputed:
                fail(entry.seq, "contents do not match entry_hash (record was altered)")
            if not entry.signature_is_valid():
                fail(entry.seq, "recipient signature does not verify")
            expected_prev = entry.entry_hash

        return ChainReport(
            ok=not problems,
            entries=len(self.entries),
            first_bad_seq=first_bad,
            problems=problems,
        )

    # -- checkpoints --------------------------------------------------------

    def _uncheckpointed(self) -> tuple[int, list[Entry]]:
        start = self.checkpoints[-1].to_seq + 1 if self.checkpoints else 0
        return start, [e for e in self.entries if e.seq >= start]

    def checkpoint(self, witness_secret_keys: Sequence[bytes], k: int) -> Checkpoint:
        """Merkle-root everything since the last checkpoint and have witnesses sign it."""
        start, pending = self._uncheckpointed()
        if not pending:
            raise ValueError("nothing to checkpoint since the last one")
        if k < 1:
            raise ValueError("a checkpoint needs at least one witness signature")
        if len(witness_secret_keys) < k:
            raise ValueError(
                f"{len(witness_secret_keys)} witness keys offered for a {k}-of-n checkpoint"
            )

        root = merkle_root([e.entry_hash for e in pending])
        cp = Checkpoint(
            index=len(self.checkpoints),
            from_seq=start,
            to_seq=pending[-1].seq,
            root=root,
            at=self.clock.now(),
            prev_root=self.checkpoints[-1].root if self.checkpoints else GENESIS_HASH,
        )
        body = pqc.canonical(cp.signed_body())
        sigs = [pqc.sig_sign(body, sk).hex() for sk in witness_secret_keys]
        signed = replace(cp, witness_sigs=sigs)
        self.checkpoints.append(signed)
        return signed

    def verify_checkpoint(
        self, cp: Checkpoint, witness_public_keys: Sequence[bytes], k: int
    ) -> bool:
        return self.count_witnesses(cp, witness_public_keys) >= k

    @staticmethod
    def count_witnesses(cp: Checkpoint, witness_public_keys: Sequence[bytes]) -> int:
        """How many *distinct recognised witness keys* signed this root.

        Counted per key rather than per signature: presenting one witness's signature
        three times is still one witness. Unrecognised signatures count for nothing,
        which is what stops an administrator from padding a checkpoint with keys they
        generated themselves.
        """
        body = pqc.canonical(cp.signed_body())
        raw: list[bytes] = []
        for hexsig in cp.witness_sigs:
            try:
                raw.append(bytes.fromhex(hexsig))
            except Exception:
                continue

        good = 0
        for pk in {pqc.pk_fingerprint(k): k for k in witness_public_keys}.values():
            if any(pqc.sig_verify(body, sig, pk) for sig in raw):
                good += 1
        return good

    def inclusion_proof(self, seq: int) -> tuple[Checkpoint, list[dict[str, str]]]:
        """Prove that entry ``seq`` is under a signed checkpoint root."""
        for cp in self.checkpoints:
            if cp.from_seq <= seq <= cp.to_seq:
                covered = [e for e in self.entries if cp.from_seq <= e.seq <= cp.to_seq]
                hashes = [e.entry_hash for e in covered]
                index = next(i for i, e in enumerate(covered) if e.seq == seq)
                return cp, merkle_proof(hashes, index)
        raise KeyError(f"entry {seq} is not covered by any checkpoint yet")

    # -- lookup -------------------------------------------------------------

    def find_by_commitment(self, commitment: str) -> Entry | None:
        for entry in self.entries:
            if entry.record.get("codeword_commitment") == commitment:
                return entry
        return None

    def find_by_recipient(self, recipient_id: str, doc_id: str | None = None) -> list[Entry]:
        return [
            e
            for e in self.entries
            if e.record.get("recipient_id") == recipient_id
            and (doc_id is None or e.record.get("doc_id") == doc_id)
        ]

    # -- persistence --------------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        return {
            "v": 1,
            "entries": [e.to_json() for e in self.entries],
            "checkpoints": [c.to_json() for c in self.checkpoints],
        }

    @staticmethod
    def from_json(obj: dict[str, Any], clock: Clock | None = None) -> "Ledger":
        ledger = Ledger(clock=clock)
        ledger.entries = [Entry.from_json(e) for e in obj.get("entries", [])]
        ledger.checkpoints = [Checkpoint.from_json(c) for c in obj.get("checkpoints", [])]
        return ledger

    def save(self, path: str | Path) -> None:
        Path(path).write_bytes(pqc.canonical(self.to_json()))

    @staticmethod
    def load(path: str | Path, clock: Clock | None = None) -> "Ledger":
        import json

        p = Path(path)
        if not p.exists():
            return Ledger(clock=clock)
        return Ledger.from_json(json.loads(p.read_bytes()), clock=clock)


# ---------------------------------------------------------------------------
# air-gapped anchoring
# ---------------------------------------------------------------------------


def checkpoint_anchor(cp: Checkpoint) -> str:
    """The compact string that goes into a QR code.

    Everything needed to challenge a later version of the ledger: the root, the range
    it covers, when it was cut, and how many witnesses stood behind it. Short enough
    to survive being printed at a readable size.
    """
    return "|".join(
        [
            "PQFW1",
            str(cp.index),
            f"{cp.from_seq}-{cp.to_seq}",
            cp.root,
            cp.at,
            str(len(cp.witness_sigs)),
        ]
    )


def export_checkpoint_qr(cp: Checkpoint, path: str | Path) -> Path:
    """Write the anchor as a PNG QR code.

    This is the whole external-anchoring story, and it is a deliberate choice rather
    than a shortcut: a printed root needs no chain, no orderer, no network and no
    running service to remain evidence. Anyone holding the paper can refute a rewritten
    ledger years later.
    """
    import qrcode

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    qrcode.make(checkpoint_anchor(cp)).save(out)
    return out
