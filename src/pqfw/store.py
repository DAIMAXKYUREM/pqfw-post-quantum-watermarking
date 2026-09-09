"""On-disk state, split along the lines of who is allowed to see what.

    state/
      seal.key                 local key for the sealed store
      distributor.sealed       SEALED: Tardos biases, codewords, slot locators, salts
      ledger.json              PUBLIC: the hash chain and its checkpoints
      packages/<doc_id>.json   PUBLIC: the broadcast ciphertext + per-recipient envelopes
      recipients/<rid>.json    the recipient's own device: their ML-KEM and ML-DSA keys
      witnesses/<i>.json       an independent witness's signing key

The split is the point, not an implementation detail. ``ledger.json`` and
``packages/`` can be handed to everybody. The sealed store holds every pre-image that
would let somebody forge, strip or transplant a fingerprint, and nothing else needs it
except tracing.

How sealed is "sealed"
----------------------
The store is encrypted at rest with AES-256-GCM under ``seal.key``. Being honest about
what that buys: it protects against a stray copy of the store file -- a backup, a repo
commit, a support bundle -- and not at all against an attacker who can read the
directory, because the key is sitting next to it. A real deployment puts that key in an
HSM or derives it from an operator passphrase; the interface here does not change when
it does. What this prototype genuinely does provide is the separation itself, which is
the part that no key custody arrangement can retrofit later.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from pqfw import pqc
from pqfw.ledger import Clock, Ledger, SystemClock
from pqfw.tardos import TardosCode, TardosParams

SEAL_LABEL = b"pqfw/seal/v1"
SEAL_AAD = b"pqfw/distributor-store/v1"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# ---------------------------------------------------------------------------
# compact array encoding
# ---------------------------------------------------------------------------


def _pack_bits(X: np.ndarray) -> list[str]:
    """One base64 string per codeword, bit-packed: m/8 bytes instead of ~2m of JSON."""
    return [_b64(np.packbits(row).tobytes()) for row in X]


def _unpack_bits(rows: Sequence[str], m: int) -> np.ndarray:
    out = np.empty((len(rows), m), dtype=np.uint8)
    for i, row in enumerate(rows):
        bits = np.unpackbits(np.frombuffer(_unb64(row), dtype=np.uint8))
        out[i] = bits[:m]
    return out


def _pack_floats(p: np.ndarray) -> str:
    """Biases as raw little-endian float64.

    Not as JSON decimals: the score, and therefore the p-value in an accusation, is
    computed from these. A trace that cannot be reproduced bit-for-bit from the stored
    state is not evidence of anything.
    """
    return _b64(np.ascontiguousarray(p, dtype="<f8").tobytes())


def _unpack_floats(text: str) -> np.ndarray:
    return np.frombuffer(_unb64(text), dtype="<f8").copy()


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------


@dataclass
class DocRecord:
    """Everything the distributor must keep in order to trace one document."""

    doc_id: str
    carrier: str
    created_at: str
    source_hash: str
    locators: list[dict[str, Any]]
    params: TardosParams
    p: np.ndarray
    X: np.ndarray
    session_order: list[str]
    """Row j of X was issued to session ``session_order[j]``.

    One codeword per *decryption session*, not per recipient. A person who decrypts
    twice gets two different fingerprints and two different ledger commitments, which
    is what makes a leak attributable to the decryption event rather than only to the
    person. Session ids look like ``r03#1``.
    """
    session_owner: dict[str, str] = field(default_factory=dict)
    """session id -> the recipient it belongs to."""
    consumed: dict[str, str] = field(default_factory=dict)
    """session id -> ISO timestamp of the decryption that spent it. Absent while unused."""
    salts: dict[str, str] = field(default_factory=dict)
    commitments: dict[str, str] = field(default_factory=dict)

    def code(self) -> TardosCode:
        return TardosCode(params=self.params, p=self.p, X=self.X)

    def index_of(self, session_id: str) -> int:
        return self.session_order.index(session_id)

    def owner_of(self, session_id: str) -> str:
        return self.session_owner.get(session_id, session_id)

    def sessions_for(self, recipient_id: str) -> list[str]:
        return [s for s in self.session_order if self.session_owner.get(s) == recipient_id]

    def next_free_session(self, recipient_id: str) -> str | None:
        """The next unspent session credential for this recipient, if any.

        Credentials are pre-issued at protect time so a recipient can decrypt without
        the distributor being reachable -- which an air-gapped deployment requires. The
        pool is finite by design: when it runs out the distributor reissues, and that
        reissue is itself a recorded act.
        """
        for session_id in self.sessions_for(recipient_id):
            if session_id not in self.consumed:
                return session_id
        return None

    def recipients(self) -> list[str]:
        seen: list[str] = []
        for session_id in self.session_order:
            owner = self.owner_of(session_id)
            if owner not in seen:
                seen.append(owner)
        return seen

    def to_json(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "carrier": self.carrier,
            "created_at": self.created_at,
            "source_hash": self.source_hash,
            "locators": self.locators,
            "params": self.params.to_json(),
            "p": _pack_floats(self.p),
            "X": _pack_bits(self.X),
            "session_order": self.session_order,
            "session_owner": self.session_owner,
            "consumed": self.consumed,
            "salts": self.salts,
            "commitments": self.commitments,
        }

    @staticmethod
    def from_json(obj: dict[str, Any]) -> "DocRecord":
        params = TardosParams.from_json(obj["params"])
        return DocRecord(
            doc_id=obj["doc_id"],
            carrier=obj["carrier"],
            created_at=obj["created_at"],
            source_hash=obj["source_hash"],
            locators=obj["locators"],
            params=params,
            p=_unpack_floats(obj["p"]),
            X=_unpack_bits(obj["X"], params.m),
            session_order=list(obj["session_order"]),
            session_owner=dict(obj.get("session_owner", {})),
            consumed=dict(obj.get("consumed", {})),
            salts=dict(obj.get("salts", {})),
            commitments=dict(obj.get("commitments", {})),
        )

    def __repr__(self) -> str:
        return (
            f"DocRecord(doc_id={self.doc_id!r}, carrier={self.carrier!r}, "
            f"slots={self.params.m}, sessions={len(self.session_order)})"
        )


@dataclass
class SealedState:
    recipients: dict[str, dict[str, str]] = field(default_factory=dict)
    docs: dict[str, DocRecord] = field(default_factory=dict)
    witness_pks: list[str] = field(default_factory=list)
    witness_threshold: int = 2

    def to_json(self) -> dict[str, Any]:
        return {
            "v": 1,
            "recipients": self.recipients,
            "docs": {k: v.to_json() for k, v in sorted(self.docs.items())},
            "witness_pks": self.witness_pks,
            "witness_threshold": self.witness_threshold,
        }

    @staticmethod
    def from_json(obj: dict[str, Any]) -> "SealedState":
        return SealedState(
            recipients=dict(obj.get("recipients", {})),
            docs={k: DocRecord.from_json(v) for k, v in obj.get("docs", {}).items()},
            witness_pks=list(obj.get("witness_pks", [])),
            witness_threshold=int(obj.get("witness_threshold", 2)),
        )


# ---------------------------------------------------------------------------
# the store
# ---------------------------------------------------------------------------


class Store:
    def __init__(self, root: str | Path, clock: Clock | None = None) -> None:
        self.root = Path(root)
        self.clock: Clock = clock or SystemClock()
        self.state = SealedState()

    # -- paths ---------------------------------------------------------------

    @property
    def seal_key_path(self) -> Path:
        return self.root / "seal.key"

    @property
    def sealed_path(self) -> Path:
        return self.root / "distributor.sealed"

    @property
    def ledger_path(self) -> Path:
        return self.root / "ledger.json"

    def package_path(self, doc_id: str) -> Path:
        return self.root / "packages" / f"{doc_id}.json"

    def recipient_path(self, recipient_id: str) -> Path:
        return self.root / "recipients" / f"{recipient_id}.json"

    def witness_path(self, index: int) -> Path:
        return self.root / "witnesses" / f"w{index:02d}.json"

    @property
    def dlt_path(self) -> Path:
        """One file per validator: each node's own replica of the chain."""
        return self.root / "dlt"

    def network(self):
        """The permissioned ledger network, loaded from disk.

        The witnesses enrolled at setup are the validators. Each holds a complete,
        independently verified replica; a receipt is only in the ledger once a quorum
        of them has accepted it.
        """
        from pqfw.dlt import LedgerNetwork

        public = self.witness_public_keys()
        secret = self.witness_secret_keys()
        if not public or len(secret) != len(public):
            raise ValueError("no validators enrolled; run enroll first")
        net = LedgerNetwork(
            list(zip(public, secret)), quorum=self.state.witness_threshold, clock=self.clock
        )
        return net.load(self.dlt_path)

    def save_network(self, network) -> None:
        network.save(self.dlt_path)

    # -- lifecycle -----------------------------------------------------------

    def init(self) -> None:
        for sub in ("packages", "recipients", "witnesses", "anchors"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        if not self.seal_key_path.exists():
            self.seal_key_path.write_bytes(os.urandom(32))
        self.save()

    def _seal_key(self) -> bytes:
        if not self.seal_key_path.exists():
            raise FileNotFoundError(
                f"{self.seal_key_path} is missing: without it the sealed store cannot be "
                f"read and no document in it can ever be traced again"
            )
        return pqc.derive_key(self.seal_key_path.read_bytes(), SEAL_LABEL)

    def save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        blob = pqc.aead_encrypt(
            self._seal_key(), pqc.canonical(self.state.to_json()), aad=SEAL_AAD
        )
        self.sealed_path.write_bytes(blob)

    def load(self) -> "Store":
        if not self.sealed_path.exists():
            self.state = SealedState()
            return self
        raw = pqc.aead_decrypt(self._seal_key(), self.sealed_path.read_bytes(), aad=SEAL_AAD)
        self.state = SealedState.from_json(json.loads(raw))
        return self

    @staticmethod
    def open(root: str | Path, clock: Clock | None = None) -> "Store":
        return Store(root, clock=clock).load()

    def exists(self) -> bool:
        return self.sealed_path.exists()

    # -- ledger --------------------------------------------------------------

    def ledger(self) -> Ledger:
        return Ledger.load(self.ledger_path, clock=self.clock)

    def save_ledger(self, ledger: Ledger) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        ledger.save(self.ledger_path)

    # -- recipients (their own devices) -------------------------------------

    def enroll_recipient(self, recipient_id: str) -> dict[str, str]:
        """Generate a recipient's keys.

        In a deployment the recipient generates these on their own device and sends
        only the public halves; the distributor never sees a private key. Here both
        halves are created in one process and the private ones are written to a
        directory that stands in for that device, so a single-machine demo can show the
        whole flow. It is a simulation boundary, not a security claim.
        """
        kem_pk, kem_sk = pqc.kem_keypair()
        sig_pk, sig_sk = pqc.sig_keypair()

        self.recipient_path(recipient_id).parent.mkdir(parents=True, exist_ok=True)
        self.recipient_path(recipient_id).write_bytes(
            pqc.canonical(
                {
                    "recipient_id": recipient_id,
                    "kem_pk": _b64(kem_pk),
                    "kem_sk": _b64(kem_sk),
                    "sig_pk": _b64(sig_pk),
                    "sig_sk": _b64(sig_sk),
                }
            )
        )
        public = {
            "recipient_id": recipient_id,
            "kem_pk": _b64(kem_pk),
            "sig_pk": _b64(sig_pk),
            "kem_pk_fpr": pqc.pk_fingerprint(kem_pk),
            "sig_pk_fpr": pqc.pk_fingerprint(sig_pk),
        }
        self.state.recipients[recipient_id] = public
        return public

    def recipient_ids(self) -> list[str]:
        return sorted(self.state.recipients)

    def recipient_public(self, recipient_id: str) -> dict[str, str]:
        if recipient_id not in self.state.recipients:
            raise KeyError(f"recipient {recipient_id!r} is not enrolled")
        return self.state.recipients[recipient_id]

    def recipient_device(self, recipient_id: str) -> dict[str, bytes]:
        path = self.recipient_path(recipient_id)
        if not path.exists():
            raise FileNotFoundError(f"no device keystore for {recipient_id!r} at {path}")
        obj = json.loads(path.read_bytes())
        return {k: _unb64(v) for k, v in obj.items() if k != "recipient_id"}

    # -- witnesses -----------------------------------------------------------

    def enroll_witnesses(self, count: int, threshold: int) -> list[str]:
        if threshold < 1 or threshold > count:
            raise ValueError(f"a {threshold}-of-{count} rule is not satisfiable")
        (self.root / "witnesses").mkdir(parents=True, exist_ok=True)
        fingerprints: list[str] = []
        self.state.witness_pks = []
        for i in range(count):
            pk, sk = pqc.sig_keypair()
            self.witness_path(i).write_bytes(
                pqc.canonical({"index": i, "sig_pk": _b64(pk), "sig_sk": _b64(sk)})
            )
            self.state.witness_pks.append(_b64(pk))
            fingerprints.append(pqc.pk_fingerprint(pk))
        self.state.witness_threshold = threshold
        return fingerprints

    def witness_public_keys(self) -> list[bytes]:
        return [_unb64(x) for x in self.state.witness_pks]

    def witness_secret_keys(self, count: int | None = None) -> list[bytes]:
        """Load witness signing keys.

        Reading n witness keys off one disk is of course not n independent witnesses.
        It is a demo of the verification rule; the rule itself does not change when the
        keys live on separate machines, which is exactly why the interface takes a list
        of secret keys and the verifier only ever sees public ones.
        """
        keys: list[bytes] = []
        wanted = count if count is not None else len(self.state.witness_pks)
        for i in range(wanted):
            path = self.witness_path(i)
            if not path.exists():
                break
            keys.append(_unb64(json.loads(path.read_bytes())["sig_sk"]))
        return keys

    # -- documents -----------------------------------------------------------

    def put_doc(self, record: DocRecord) -> None:
        self.state.docs[record.doc_id] = record

    def doc(self, doc_id: str) -> DocRecord:
        if doc_id not in self.state.docs:
            known = ", ".join(sorted(self.state.docs)) or "none"
            raise KeyError(f"unknown doc_id {doc_id!r}; the store holds: {known}")
        return self.state.docs[doc_id]

    def doc_ids(self) -> list[str]:
        return sorted(self.state.docs)

    def salt(self, doc_id: str, recipient_id: str) -> bytes:
        return bytes.fromhex(self.doc(doc_id).salts[recipient_id])
