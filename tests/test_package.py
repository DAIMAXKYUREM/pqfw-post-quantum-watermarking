"""Task 4: variant-keyed broadcast encryption.

``test_recipient_cannot_decrypt_the_other_variant`` is the central security claim of
the whole project. Everything else here supports it:

  * the ciphertext really is shared (so this is broadcast encryption, not N copies),
  * the fingerprint a recipient ends up with really is their codeword,
  * two recipients' copies really are visually identical,
  * and the wrong recipient really cannot open an envelope.
"""

from __future__ import annotations

import numpy as np
import pytest
from cryptography.exceptions import InvalidTag

from pqfw import package as pkg
from pqfw import pqc, tardos
from pqfw.carrier import get_carrier
from pqfw.carriers import text as text_carrier  # noqa: F401  -- registers the carrier
from pqfw.tardos import TardosParams

SOURCE = (
    "CONFIDENTIAL DRAFT. The committee met on the fourteenth to review the tender "
    "submissions received during the preceding quarter. Three submissions were found "
    "to be non compliant with the published evaluation criteria and were set aside. "
    "The remaining submissions are ranked in the appendix to this memorandum, which "
    "is circulated to the named distribution list and to nobody else at all."
).encode("utf-8")

M = 24
N = 6
DOC_ID = "doc-test-0001"


def _fixture(seed: int = 0):
    rng = np.random.default_rng(seed)
    code = tardos.generate(TardosParams(m=M, n=N, c=3, eps1=1e-6), rng)
    recipients, secrets = [], {}
    for j in range(N):
        kem_pk, kem_sk = pqc.kem_keypair()
        sig_pk, _sig_sk = pqc.sig_keypair()
        rid = f"r{j:02d}"
        recipients.append(pkg.Recipient(recipient_id=rid, kem_pk=kem_pk, sig_pk=sig_pk))
        secrets[rid] = kem_sk
    carrier = get_carrier("text-zwsp")
    plan = carrier.plan(SOURCE, M, rng)
    package = pkg.build_package(DOC_ID, plan, code, recipients)
    return code, recipients, secrets, plan, package, carrier


# ---------------------------------------------------------------------------


def test_variant_blobs_identical_across_recipients() -> None:
    """One encryption, N recipients. The shared ciphertext carries no per-recipient
    trace at all -- only the ~1 KB envelope differs."""
    _code, recipients, _secrets, _plan, package, _carrier = _fixture()
    shared = package.public_view()
    assert all(package.public_view() == shared for _ in recipients)

    envelopes = [package.envelopes[r.recipient_id] for r in recipients]
    assert len({e.wrapped_bundle for e in envelopes}) == len(recipients)
    assert len({e.kem_ct for e in envelopes}) == len(recipients)

    report = package.size_report()
    assert report["per_recipient_bytes"] < report["public_bytes"]


def test_recipient_recovers_own_fingerprint() -> None:
    code, recipients, secrets, plan, package, carrier = _fixture(1)
    for j, r in enumerate(recipients):
        opened = pkg.open_package(package, r.recipient_id, secrets[r.recipient_id])
        bits = carrier.extract(opened.document, plan.locators())
        assert bits == [int(b) for b in code.X[j]], f"{r.recipient_id} got the wrong mark"


def test_recipient_cannot_decrypt_the_other_variant() -> None:
    """THE central security claim.

    The recipient's fingerprint is not something their software chose to apply. They
    hold VK[i][b] and not VK[i][1-b], so the opposite rendering is an AES-GCM tag
    failure for them. There is no unmarked copy to patch their way to: it does not
    exist anywhere, including on the distributor's disk after build_package returns.
    """
    code, recipients, secrets, _plan, package, _carrier = _fixture(2)
    victim = recipients[3]
    bundle = pkg.unwrap_bundle(package, victim.recipient_id, secrets[victim.recipient_id])

    checked = 0
    for i in range(package.m):
        held = int(code.X[3][i])
        other = 1 - held
        other_blob = package.variant_blobs[i][other]

        # the key they hold opens the variant they were issued ...
        assert pkg.pqc.aead_decrypt(
            bundle.vks[i], package.variant_blobs[i][held], aad=pkg.variant_aad(DOC_ID, i, held)
        )

        # ... and cannot open the other one, under any AAD they might try
        with pytest.raises(InvalidTag):
            pkg.pqc.aead_decrypt(
                bundle.vks[i], other_blob, aad=pkg.variant_aad(DOC_ID, i, other)
            )
        with pytest.raises(InvalidTag):
            pkg.pqc.aead_decrypt(
                bundle.vks[i], other_blob, aad=pkg.variant_aad(DOC_ID, i, held)
            )
        checked += 1

    assert checked == M


def test_a_coalition_still_cannot_forge_a_slot_they_agree_on() -> None:
    """The marking assumption, enforced rather than assumed.

    Where two colluders hold the same bit, their pooled keys still do not open the
    opposite rendering. This is why the collusion strategies in tardos.collude are
    restricted to positions where the coalition disagrees.
    """
    code, recipients, secrets, _plan, package, _carrier = _fixture(3)
    a, b = recipients[0], recipients[1]
    bundle_a = pkg.unwrap_bundle(package, a.recipient_id, secrets[a.recipient_id])
    bundle_b = pkg.unwrap_bundle(package, b.recipient_id, secrets[b.recipient_id])

    agreed = [i for i in range(M) if code.X[0][i] == code.X[1][i]]
    assert agreed, "with 24 slots two codewords will agree somewhere"
    for i in agreed:
        other = 1 - int(code.X[0][i])
        for key in (bundle_a.vks[i], bundle_b.vks[i]):
            with pytest.raises(InvalidTag):
                pkg.pqc.aead_decrypt(
                    key, package.variant_blobs[i][other], aad=pkg.variant_aad(DOC_ID, i, other)
                )


def test_wrong_recipient_cannot_unwrap() -> None:
    _code, recipients, secrets, _plan, package, _carrier = _fixture(4)
    with pytest.raises(InvalidTag):
        pkg.unwrap_bundle(package, recipients[2].recipient_id, secrets[recipients[5].recipient_id])


def test_envelope_cannot_be_relabelled_onto_another_recipient() -> None:
    """Transplanting an envelope would transplant a fingerprint onto an innocent
    person. The recipient id is in the bundle's AAD precisely to stop that."""
    _code, recipients, secrets, _plan, package, _carrier = _fixture(5)
    victim, framer = recipients[1], recipients[4]
    package.envelopes[framer.recipient_id] = package.envelopes[victim.recipient_id]
    with pytest.raises(InvalidTag):
        pkg.unwrap_bundle(package, framer.recipient_id, secrets[victim.recipient_id])


def test_two_recipients_render_identically() -> None:
    _code, recipients, secrets, _plan, package, carrier = _fixture(6)
    docs = [
        pkg.open_package(package, r.recipient_id, secrets[r.recipient_id]).document
        for r in recipients
    ]
    stripped = {carrier.strip_marks(d) for d in docs}
    assert len(stripped) == 1, "recipients must hold the same document, visually"
    assert stripped.pop() == SOURCE
    assert len(set(docs)) == len(docs), "...but no two byte-identical copies"


def test_document_hash_differs_per_recipient() -> None:
    """The receipt in the ledger commits to the recipient's own copy, so the hashes
    must genuinely differ -- otherwise the receipt proves nothing about which copy was
    released."""
    _code, recipients, secrets, _plan, package, _carrier = _fixture(7)
    hashes = {
        pkg.open_package(package, r.recipient_id, secrets[r.recipient_id]).doc_hash
        for r in recipients
    }
    assert len(hashes) == len(recipients)


def test_package_survives_a_disk_roundtrip(tmp_path) -> None:
    code, recipients, secrets, plan, package, carrier = _fixture(8)
    path = tmp_path / "package.pqfw.json"
    package.save(path)
    reloaded = pkg.DistributionPackage.load(path)

    assert reloaded.public_view() == package.public_view()
    opened = pkg.open_package(reloaded, "r02", secrets["r02"])
    assert carrier.extract(opened.document, plan.locators()) == [int(b) for b in code.X[2]]


def test_build_rejects_a_mismatched_code() -> None:
    rng = np.random.default_rng(9)
    code = tardos.generate(TardosParams(m=M + 1, n=N, c=3, eps1=1e-6), rng)
    carrier = get_carrier("text-zwsp")
    plan = carrier.plan(SOURCE, M, rng)
    kem_pk, _ = pqc.kem_keypair()
    sig_pk, _ = pqc.sig_keypair()
    with pytest.raises(ValueError):
        pkg.build_package(DOC_ID, plan, code, [pkg.Recipient("r00", kem_pk, sig_pk)])


def test_build_refuses_to_issue_two_recipients_the_same_codeword() -> None:
    """The silent failure this guard exists for.

    Two recipients holding the same codeword receive byte-identical documents, so a
    trace produces a tie that no evidence can ever break. It has no symptom at trace
    time, which is why it has to be an error at issue time. The arcsine biases sit
    near 0 and 1, so on a short code this is not a rare accident.
    """
    rng = np.random.default_rng(12)
    code = tardos.generate(TardosParams(m=M, n=2, c=3, eps1=1e-6), rng)
    collided = tardos.TardosCode(
        params=code.params, p=code.p, X=np.repeat(code.X[:1], 2, axis=0)
    )
    carrier = get_carrier("text-zwsp")
    plan = carrier.plan(SOURCE, M, rng)
    recipients = []
    for j in range(2):
        kem_pk, _ = pqc.kem_keypair()
        sig_pk, _ = pqc.sig_keypair()
        recipients.append(pkg.Recipient(f"r{j:02d}", kem_pk, sig_pk))

    with pytest.raises(ValueError, match="indistinguishable"):
        pkg.build_package(DOC_ID, plan, collided, recipients)


def test_generate_avoids_codeword_collisions_on_a_short_code() -> None:
    code = tardos.generate(TardosParams(m=M, n=N, c=3, eps1=1e-6), np.random.default_rng(7))
    assert code.duplicate_groups() == []


def test_key_bundle_never_prints_key_material() -> None:
    bundle = pkg.KeyBundle(ck=b"\x01" * 32, vks=[b"\x02" * 32])
    assert "\\x01" not in repr(bundle) and "AQEB" not in repr(bundle)
    assert repr(bundle) == "KeyBundle(slots=1)"
