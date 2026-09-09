"""Post-quantum primitives and the small symmetric helpers built on top of them.

Everything in PQFW that is cryptographically load-bearing routes through this module:

* **ML-KEM-768** (FIPS 203) wraps each recipient's key bundle.
* **ML-DSA-65** (FIPS 204) signs decryption receipts and ledger checkpoints.
* **AES-256-GCM** encrypts base segments and slot variants. The AAD binds every
  ciphertext to its (doc_id, slot, variant) position, so a variant blob cannot be
  lifted out of one slot and replayed into another.
* **HKDF-SHA3-256** separates the bundle-wrapping key from the raw KEM shared secret.

There is deliberately no cleverness here. The novelty of the project lives in
package.py and tardos.py; this file exists so that those modules never touch a native
handle or a nonce directly.

Secrets never appear in a log line or a repr from this module.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from contextlib import contextmanager
from typing import Any, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA3_256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class _DropFaulthandlerNotice(logging.Filter):
    """liboqs-python attaches its own INFO handler to stdout at import time and
    announces its faulthandler state. That single line lands in the middle of CLI
    output and in any JSON a caller is piping. Drop just that record and leave the
    native-build chatter, which is genuinely useful on a first run, alone.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return "faulthandler" not in record.getMessage()


# Installed *before* the oqs import: the logger object is created by this call, oqs's
# own getLogger returns the same object, and neither setLevel nor addHandler clears
# filters. Setting a level here would not work -- oqs overwrites it.
logging.getLogger("oqs.oqs").addFilter(_DropFaulthandlerNotice())

import oqs  # noqa: E402  -- import order is load-bearing, see above

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


# ---------------------------------------------------------------------------
# canonical serialization
# ---------------------------------------------------------------------------


def canonical(obj: Any) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8.

    Anything hashed or signed goes through this. A hash over json.dumps defaults is a
    silent correctness bug: it depends on dict insertion order, which survives a
    round-trip through Python but not through a file, another language, or another
    version.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha3_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def canonical_hash(obj: Any) -> str:
    return sha3_hex(canonical(obj))


# ---------------------------------------------------------------------------
# ML-KEM-768
# ---------------------------------------------------------------------------


@contextmanager
def _kem(secret_key: bytes | None = None) -> Iterator[Any]:
    """Own the native handle for exactly as long as we need it."""
    obj = oqs.KeyEncapsulation(KEM_ALG, secret_key)
    try:
        yield obj
    finally:
        obj.free()


@contextmanager
def _sig(secret_key: bytes | None = None) -> Iterator[Any]:
    obj = oqs.Signature(SIG_ALG, secret_key)
    try:
        yield obj
    finally:
        obj.free()


def kem_keypair() -> tuple[bytes, bytes]:
    """Return (public_key, secret_key) for ML-KEM-768."""
    with _kem() as kem:
        public_key = bytes(kem.generate_keypair())
        secret_key = bytes(kem.export_secret_key())
    return public_key, secret_key


def kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Return (ciphertext, shared_secret)."""
    with _kem() as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return bytes(ciphertext), bytes(shared_secret)


def kem_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Return the shared secret.

    ML-KEM uses *implicit rejection*: a wrong secret key does not raise, it returns a
    different pseudorandom shared secret. The AEAD tag check downstream is what
    actually rejects the wrong recipient.
    """
    with _kem(secret_key) as kem:
        return bytes(kem.decap_secret(ciphertext))


# ---------------------------------------------------------------------------
# ML-DSA-65
# ---------------------------------------------------------------------------


def sig_keypair() -> tuple[bytes, bytes]:
    with _sig() as sig:
        public_key = bytes(sig.generate_keypair())
        secret_key = bytes(sig.export_secret_key())
    return public_key, secret_key


def sig_sign(message: bytes, secret_key: bytes) -> bytes:
    with _sig(secret_key) as sig:
        return bytes(sig.sign(message))


def sig_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """False on any failure, including a structurally malformed signature.

    A verifier that raises on garbage turns an attack into a crash report, and every
    caller here treats "invalid" and "unparseable" identically.
    """
    try:
        with _sig() as sig:
            return bool(sig.verify(message, signature, public_key))
    except Exception:
        return False


def pk_fingerprint(public_key: bytes) -> str:
    """Short stable handle for a public key: first 32 hex chars of SHA3-256.

    128 bits of a collision-resistant hash, which is enough to name a key inside a
    receipt without carrying 1952 bytes of it around.
    """
    return sha3_hex(public_key)[:32]


# ---------------------------------------------------------------------------
# symmetric layer
# ---------------------------------------------------------------------------


def random_key() -> bytes:
    return os.urandom(KEY_LEN)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM. Output is nonce || ciphertext || tag.

    A fresh random 12-byte nonce per call. Variant keys are each used exactly once in
    this system, but the counter that would *prove* that does not exist offline, so we
    pay for randomness rather than assume discipline.
    """
    if len(key) != KEY_LEN:
        raise ValueError("AES-256-GCM needs a 32-byte key")
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag on a wrong key or wrong AAD.

    That exception *is* the enforcement mechanism for the whole fingerprinting scheme:
    a recipient holding the wrong variant key gets a tag failure, not a fallback.
    """
    if len(key) != KEY_LEN:
        raise ValueError("AES-256-GCM needs a 32-byte key")
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise ValueError("AEAD blob is too short to hold a nonce and a tag")
    nonce, body = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, body, aad)


def derive_key(shared_secret: bytes, label: bytes) -> bytes:
    """HKDF-SHA3-256, no salt, info=label, 32 bytes out.

    The KEM shared secret is never used as an AEAD key directly: the label gives us
    domain separation, so the same shared secret can key different purposes without
    those purposes interacting.
    """
    return HKDF(algorithm=SHA3_256(), length=KEY_LEN, salt=None, info=label).derive(shared_secret)


def alg_report() -> dict[str, str]:
    """What the runtime is actually using.

    Printed by ``pqfw audit`` so that a reviewer never has to trust a README claim
    about which primitives are in play.
    """
    return {
        "kem": KEM_ALG,
        "sig": SIG_ALG,
        "aead": "AES-256-GCM",
        "hash": "SHA3-256",
        "kdf": "HKDF-SHA3-256",
        "liboqs": str(oqs.oqs_version()),
        "liboqs_python": str(oqs.oqs_python_version()),
    }
