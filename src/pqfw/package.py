"""Variant-keyed broadcast encryption: the fingerprint is a consequence of key
possession, not of software behaviour.

The document is split into m + 1 base segments and m mark slots. Each slot has two
visually identical renderings. Both renderings are encrypted -- under *different* keys
-- and both ship to everybody. A recipient's wrapped bundle contains the content key
plus exactly one variant key per slot, selected by their Tardos codeword bit.

So the recipient does not *choose* to be fingerprinted, and cannot decline. Handing
them variant key VK[i][0] and withholding VK[i][1] means slot i of their copy is the
zero rendering or nothing at all: AES-GCM's tag check is what enforces it, and there
is no code path around a tag check. Patching the client does not help. Reverse
engineering the client does not help. There is no unmarked copy anywhere in the
system -- not on the distributor's disk, not in the package, not in transit.

What ships
----------
    public part   base blobs + 2m variant blobs      identical bytes for everyone
    private part  ML-KEM-768 ciphertext + wrapped bundle   ~1 KB + 32 bytes per slot

Only the private part differs per recipient, and it is independent of the document's
size. That is what makes "encrypt once, distribute to N" real rather than N
encryptions with a shared name.

A note on the AAD
-----------------
Every ciphertext is bound by its associated data to the exact position it occupies:
(doc_id, kind, index) for base segments, (doc_id, slot, variant) for variants, and
(doc_id, recipient_id) for the wrapped bundle. The recipient binding on the bundle is
one step beyond the original design note, which bound the bundle to doc_id alone: it
costs nothing and it stops an envelope being relabelled from one recipient to another,
which would otherwise transplant a fingerprint onto an innocent person.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from pqfw import pqc
from pqfw.carrier import CarrierPlan, get_carrier
from pqfw.tardos import TardosCode

BUNDLE_LABEL = b"pqfw/bundle/v1"
FORMAT_VERSION = 1


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# ---------------------------------------------------------------------------
# associated data
# ---------------------------------------------------------------------------


def base_aad(doc_id: str, index: int) -> bytes:
    return pqc.canonical({"doc_id": doc_id, "kind": "base", "index": index})


def variant_aad(doc_id: str, slot: int, variant: int) -> bytes:
    return pqc.canonical({"doc_id": doc_id, "slot": slot, "variant": variant})


def bundle_aad(doc_id: str, recipient_id: str) -> bytes:
    return pqc.canonical({"doc_id": doc_id, "kind": "bundle", "recipient_id": recipient_id})


# ---------------------------------------------------------------------------
# data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Recipient:
    """The public half of an enrolled recipient."""

    recipient_id: str
    kem_pk: bytes
    sig_pk: bytes

    def to_json(self) -> dict[str, str]:
        return {
            "recipient_id": self.recipient_id,
            "kem_pk": _b64(self.kem_pk),
            "sig_pk": _b64(self.sig_pk),
            "kem_pk_fpr": pqc.pk_fingerprint(self.kem_pk),
            "sig_pk_fpr": pqc.pk_fingerprint(self.sig_pk),
        }

    @staticmethod
    def from_json(obj: dict[str, str]) -> "Recipient":
        return Recipient(
            recipient_id=obj["recipient_id"],
            kem_pk=_unb64(obj["kem_pk"]),
            sig_pk=_unb64(obj["sig_pk"]),
        )


@dataclass(frozen=True)
class KeyBundle:
    """What one recipient gets: the content key and one variant key per slot.

    Never serialised in the clear, never logged, never printed.
    """

    ck: bytes
    vks: list[bytes]

    def encode(self) -> bytes:
        # Canonical JSON as the design requires, but the m keys travel as one base64
        # blob rather than m base64 strings: a fixed-width key vector has no ordering
        # to canonicalise, and the list form adds about 10% to every bundle for
        # punctuation alone.
        return pqc.canonical(
            {"v": FORMAT_VERSION, "ck": _b64(self.ck), "vks": _b64(b"".join(self.vks))}
        )

    @staticmethod
    def decode(raw: bytes) -> "KeyBundle":
        import json

        obj = json.loads(raw.decode("utf-8"))
        if int(obj.get("v", 0)) != FORMAT_VERSION:
            raise ValueError(f"unsupported bundle version {obj.get('v')!r}")
        flat = _unb64(obj["vks"])
        if len(flat) % pqc.KEY_LEN != 0:
            raise ValueError("bundle variant-key blob is not a whole number of keys")
        vks = [flat[i : i + pqc.KEY_LEN] for i in range(0, len(flat), pqc.KEY_LEN)]
        return KeyBundle(ck=_unb64(obj["ck"]), vks=vks)

    def __repr__(self) -> str:
        return f"KeyBundle(slots={len(self.vks)})"  # never the key material


@dataclass(frozen=True)
class Envelope:
    """A recipient's private part of the package."""

    kem_ct: bytes
    wrapped_bundle: bytes

    @property
    def size_bytes(self) -> int:
        return len(self.kem_ct) + len(self.wrapped_bundle)


@dataclass(frozen=True)
class DistributionPackage:
    doc_id: str
    carrier: str
    base_blobs: list[bytes]
    variant_blobs: list[tuple[bytes, bytes]]
    """variant_blobs[i] = (ciphertext of rendering 0, ciphertext of rendering 1)."""
    envelopes: dict[str, Envelope]
    meta: dict[str, Any]

    @property
    def m(self) -> int:
        return len(self.variant_blobs)

    # -- the invariant that makes this broadcast encryption ------------------

    def public_view(self) -> bytes:
        """The bytes every recipient receives, canonically serialised.

        Two recipients comparing this must get identical output. If anything
        recipient-specific ever leaks into the shared ciphertext, this is what catches
        it -- and it would be a real break, because a recipient who can tell their copy
        of the ciphertext from someone else's can strip the difference.
        """
        return pqc.canonical(
            {
                "doc_id": self.doc_id,
                "carrier": self.carrier,
                "base": [_b64(b) for b in self.base_blobs],
                "variants": [[_b64(v0), _b64(v1)] for v0, v1 in self.variant_blobs],
            }
        )

    def public_hash(self) -> str:
        return pqc.sha3_hex(self.public_view())

    # -- serialisation -------------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        return {
            "v": FORMAT_VERSION,
            "doc_id": self.doc_id,
            "carrier": self.carrier,
            "base": [_b64(b) for b in self.base_blobs],
            "variants": [[_b64(a), _b64(b)] for a, b in self.variant_blobs],
            "envelopes": {
                rid: {"kem_ct": _b64(e.kem_ct), "wrapped_bundle": _b64(e.wrapped_bundle)}
                for rid, e in sorted(self.envelopes.items())
            },
            "meta": self.meta,
        }

    @staticmethod
    def from_json(obj: dict[str, Any]) -> "DistributionPackage":
        return DistributionPackage(
            doc_id=obj["doc_id"],
            carrier=obj["carrier"],
            base_blobs=[_unb64(x) for x in obj["base"]],
            variant_blobs=[(_unb64(a), _unb64(b)) for a, b in obj["variants"]],
            envelopes={
                rid: Envelope(_unb64(e["kem_ct"]), _unb64(e["wrapped_bundle"]))
                for rid, e in obj["envelopes"].items()
            },
            meta=obj.get("meta", {}),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_bytes(pqc.canonical(self.to_json()))

    @staticmethod
    def load(path: str | Path) -> "DistributionPackage":
        import json

        return DistributionPackage.from_json(json.loads(Path(path).read_bytes()))

    def size_report(self) -> dict[str, int]:
        public = len(self.public_view())
        per_recipient = (
            min(e.size_bytes for e in self.envelopes.values()) if self.envelopes else 0
        )
        return {
            "slots": self.m,
            "recipients": len(self.envelopes),
            "public_bytes": public,
            "per_recipient_bytes": per_recipient,
            "total_bytes": public + per_recipient * len(self.envelopes),
        }


# ---------------------------------------------------------------------------
# distribution
# ---------------------------------------------------------------------------


def build_package(
    doc_id: str,
    plan: CarrierPlan,
    code: TardosCode,
    recipients: Sequence[Recipient],
) -> DistributionPackage:
    """Encrypt once, for everybody, with a different fingerprint waiting for each.

    Recipient at position j in ``recipients`` is issued codeword ``code.X[j]``.
    """
    m = plan.m
    if code.params.m != m:
        raise ValueError(f"code has {code.params.m} slots, plan has {m}")
    if code.params.n < len(recipients):
        raise ValueError(
            f"code was generated for {code.params.n} recipients, {len(recipients)} given"
        )
    if len({r.recipient_id for r in recipients}) != len(recipients):
        raise ValueError("recipient ids must be unique")

    # Defence in depth against the one failure that leaves no trace at trace time:
    # two recipients issued the same codeword receive byte-identical documents and can
    # never be told apart. tardos.generate already avoids it; refusing here means a
    # hand-built or deserialised code cannot reintroduce it silently.
    issued = TardosCode(params=code.params, p=code.p, X=code.X[: len(recipients)])
    collisions = issued.duplicate_groups()
    if collisions:
        pairs = ", ".join(
            "/".join(recipients[j].recipient_id for j in group) for group in collisions[:3]
        )
        raise ValueError(
            f"identical codewords issued to {pairs}: those recipients would be "
            f"indistinguishable in a trace. Lengthen the code (m={m})."
        )

    content_key = pqc.random_key()
    variant_keys: list[tuple[bytes, bytes]] = [
        (pqc.random_key(), pqc.random_key()) for _ in range(m)
    ]

    base_blobs = [
        pqc.aead_encrypt(content_key, segment, aad=base_aad(doc_id, i))
        for i, segment in enumerate(plan.base_segments)
    ]
    variant_blobs = [
        (
            pqc.aead_encrypt(variant_keys[i][0], slot.variant_0, aad=variant_aad(doc_id, i, 0)),
            pqc.aead_encrypt(variant_keys[i][1], slot.variant_1, aad=variant_aad(doc_id, i, 1)),
        )
        for i, slot in enumerate(plan.slots)
    ]

    envelopes: dict[str, Envelope] = {}
    for j, recipient in enumerate(recipients):
        codeword = code.X[j]
        bundle = KeyBundle(
            ck=content_key,
            vks=[variant_keys[i][int(codeword[i])] for i in range(m)],
        )
        kem_ct, shared_secret = pqc.kem_encapsulate(recipient.kem_pk)
        wrap_key = pqc.derive_key(shared_secret, BUNDLE_LABEL)
        wrapped = pqc.aead_encrypt(
            wrap_key, bundle.encode(), aad=bundle_aad(doc_id, recipient.recipient_id)
        )
        envelopes[recipient.recipient_id] = Envelope(kem_ct=kem_ct, wrapped_bundle=wrapped)

    return DistributionPackage(
        doc_id=doc_id,
        carrier=plan.carrier,
        base_blobs=base_blobs,
        variant_blobs=variant_blobs,
        envelopes=envelopes,
        meta={
            "slots": m,
            "recipients": [r.recipient_id for r in recipients],
            "algorithms": pqc.alg_report(),
            "carrier_notes": plan.notes or {},
        },
    )


# ---------------------------------------------------------------------------
# reception
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OpenedDocument:
    document: bytes
    doc_hash: str
    slots_opened: int


def unwrap_bundle(
    package: DistributionPackage, recipient_id: str, kem_sk: bytes
) -> KeyBundle:
    """Recover this recipient's keys, or fail.

    ML-KEM's implicit rejection means a wrong secret key produces a wrong shared
    secret rather than an error; the AEAD tag on the wrapped bundle is what turns that
    into a refusal.
    """
    if recipient_id not in package.envelopes:
        raise KeyError(f"no envelope for recipient {recipient_id!r} in this package")
    envelope = package.envelopes[recipient_id]
    shared_secret = pqc.kem_decapsulate(envelope.kem_ct, kem_sk)
    wrap_key = pqc.derive_key(shared_secret, BUNDLE_LABEL)
    raw = pqc.aead_decrypt(
        wrap_key, envelope.wrapped_bundle, aad=bundle_aad(package.doc_id, recipient_id)
    )
    bundle = KeyBundle.decode(raw)
    if len(bundle.vks) != package.m:
        raise ValueError(
            f"bundle holds {len(bundle.vks)} variant keys for a {package.m}-slot package"
        )
    return bundle


def open_package(
    package: DistributionPackage, recipient_id: str, kem_sk: bytes
) -> OpenedDocument:
    """Decrypt to this recipient's uniquely fingerprinted copy.

    Each slot is tried against variant 0 and then variant 1; exactly one succeeds,
    because the bundle holds exactly one of the two keys. The recipient never sees the
    other rendering and cannot construct it.
    """
    bundle = unwrap_bundle(package, recipient_id, kem_sk)
    carrier = get_carrier(package.carrier)

    base_segments = [
        pqc.aead_decrypt(bundle.ck, blob, aad=base_aad(package.doc_id, i))
        for i, blob in enumerate(package.base_blobs)
    ]

    chosen: list[bytes] = []
    for i, (blob0, blob1) in enumerate(package.variant_blobs):
        rendering = _open_one_slot(package.doc_id, i, blob0, blob1, bundle.vks[i])
        chosen.append(rendering)

    document = carrier.assemble(base_segments, chosen)
    return OpenedDocument(
        document=document, doc_hash=pqc.sha3_hex(document), slots_opened=len(chosen)
    )


def _open_one_slot(
    doc_id: str, index: int, blob0: bytes, blob1: bytes, key: bytes
) -> bytes:
    from cryptography.exceptions import InvalidTag

    for variant, blob in ((0, blob0), (1, blob1)):
        try:
            return pqc.aead_decrypt(key, blob, aad=variant_aad(doc_id, index, variant))
        except InvalidTag:
            continue
    raise InvalidTag(
        f"slot {index}: the bundled key opens neither variant -- the package and the "
        f"bundle do not belong together"
    )


# ---------------------------------------------------------------------------
# convenience for the CLI and the evaluation harness
# ---------------------------------------------------------------------------


def plan_and_build(
    doc_id: str,
    source: bytes,
    carrier_name: str,
    code: TardosCode,
    recipients: Sequence[Recipient],
    rng: np.random.Generator,
) -> tuple[DistributionPackage, CarrierPlan]:
    carrier = get_carrier(carrier_name)
    plan = carrier.plan(source, code.params.m, rng)
    return build_package(doc_id, plan, code, recipients), plan
