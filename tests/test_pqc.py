"""Task 1: the PQC wrappers. Boring on purpose -- every clever idea in this project
sits on top of these six functions, so they get to be dull and well tested.
"""

import pytest
from cryptography.exceptions import InvalidTag

from pqfw import pqc


def test_kem_roundtrip() -> None:
    pk, sk = pqc.kem_keypair()
    ct, ss_sender = pqc.kem_encapsulate(pk)
    ss_receiver = pqc.kem_decapsulate(ct, sk)
    assert ss_sender == ss_receiver
    assert len(ss_sender) == 32


def test_kem_wrong_key_fails() -> None:
    """ML-KEM has implicit rejection: a wrong secret key does not raise, it yields a
    different shared secret. Assert inequality, not an exception -- asserting the wrong
    thing here would hide a real break."""
    pk_a, sk_a = pqc.kem_keypair()
    _pk_b, sk_b = pqc.kem_keypair()
    ct, ss_sender = pqc.kem_encapsulate(pk_a)
    assert pqc.kem_decapsulate(ct, sk_a) == ss_sender
    assert pqc.kem_decapsulate(ct, sk_b) != ss_sender


def test_sig_roundtrip() -> None:
    pk, sk = pqc.sig_keypair()
    msg = b"a decryption receipt"
    sig = pqc.sig_sign(msg, sk)
    assert pqc.sig_verify(msg, sig, pk) is True


def test_sig_tamper_fails() -> None:
    pk, sk = pqc.sig_keypair()
    msg = bytearray(b"a decryption receipt")
    sig = pqc.sig_sign(bytes(msg), sk)
    msg[3] ^= 0x01
    assert pqc.sig_verify(bytes(msg), sig, pk) is False


def test_sig_wrong_public_key_fails() -> None:
    pk_a, sk_a = pqc.sig_keypair()
    pk_b, _sk_b = pqc.sig_keypair()
    sig = pqc.sig_sign(b"m", sk_a)
    assert pqc.sig_verify(b"m", sig, pk_a) is True
    assert pqc.sig_verify(b"m", sig, pk_b) is False


def test_aead_roundtrip_and_aad_binding() -> None:
    key = pqc.random_key()
    blob = pqc.aead_encrypt(key, b"variant zero", aad=b"slot=0,variant=0")
    assert pqc.aead_decrypt(key, blob, aad=b"slot=0,variant=0") == b"variant zero"
    with pytest.raises(InvalidTag):
        pqc.aead_decrypt(key, blob, aad=b"slot=0,variant=1")


def test_aead_wrong_key_raises() -> None:
    blob = pqc.aead_encrypt(pqc.random_key(), b"x", aad=b"")
    with pytest.raises(InvalidTag):
        pqc.aead_decrypt(pqc.random_key(), blob, aad=b"")


def test_aead_nonce_is_unique() -> None:
    key = pqc.random_key()
    a = pqc.aead_encrypt(key, b"same plaintext", aad=b"")
    b = pqc.aead_encrypt(key, b"same plaintext", aad=b"")
    assert a[:12] != b[:12]
    assert a != b


def test_derive_key_is_deterministic_and_label_separated() -> None:
    ss = b"\x01" * 32
    assert pqc.derive_key(ss, b"pqfw/bundle/v1") == pqc.derive_key(ss, b"pqfw/bundle/v1")
    assert pqc.derive_key(ss, b"pqfw/bundle/v1") != pqc.derive_key(ss, b"pqfw/other/v1")
    assert len(pqc.derive_key(ss, b"x")) == 32


def test_pk_fingerprint_is_stable_and_short() -> None:
    pk, _sk = pqc.sig_keypair()
    fpr = pqc.pk_fingerprint(pk)
    assert fpr == pqc.pk_fingerprint(pk)
    assert len(fpr) == 32
    assert all(c in "0123456789abcdef" for c in fpr)


def test_canonical_json_is_stable_under_key_order() -> None:
    assert pqc.canonical({"b": 1, "a": [1, 2]}) == pqc.canonical({"a": [1, 2], "b": 1})
    assert pqc.canonical({"a": 1}) == b'{"a":1}'


def test_algorithms_are_the_declared_post_quantum_ones() -> None:
    assert pqc.KEM_ALG == "ML-KEM-768"
    assert pqc.SIG_ALG == "ML-DSA-65"
