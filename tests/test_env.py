"""Task 0 gate: the PQC primitives the whole design rests on must actually exist.

If this file fails there is no point running anything else. We do not fall back to
RSA or Ed25519 -- post-quantum is the premise of the project, not an optimisation.
"""

import oqs

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"


def test_kem_mechanism_list_is_non_empty() -> None:
    assert len(oqs.get_enabled_kem_mechanisms()) > 0


def test_sig_mechanism_list_is_non_empty() -> None:
    assert len(oqs.get_enabled_sig_mechanisms()) > 0


def test_ml_kem_768_is_enabled() -> None:
    assert KEM_ALG in oqs.get_enabled_kem_mechanisms()


def test_ml_dsa_65_is_enabled() -> None:
    assert SIG_ALG in oqs.get_enabled_sig_mechanisms()
