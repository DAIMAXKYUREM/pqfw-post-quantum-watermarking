---
title: PQFW — Post-Quantum Forensic Watermarking
emoji: 🔏
colorFrom: indigo
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: Encrypt once for N recipients; each copy is uniquely fingerprinted by key possession, and a leak traces back with a provable error bound.
---

# PQFW — Post-Quantum Forensic Watermarking

A document is encrypted **once** for N recipients. Each recipient's decryption produces
a visually identical but **uniquely fingerprinted** copy — and the fingerprint is
enforced by **which keys they hold**, not by software that politely applies a watermark.
A leaked copy traces back to a recipient with a **provable** false-accusation
probability, corroborated by a tamper-evident append-only ledger.

Every number on this page is computed live by the real library: **ML-KEM-768**
(FIPS 203) via `liboqs`, **ML-DSA-65** (FIPS 204) receipts, AES-256-GCM variant
encryption, SHA3-256 hash chaining, and a symmetric Tardos fingerprinting code.
Nothing is mocked or pre-baked.

## What to try

1. **Enrol** a dozen recipients — real post-quantum key pairs, generated on demand.
2. **Protect** the sample memo. Note that the ciphertext is byte-identical for everyone;
   only a ~14 KB wrapped key bundle differs per recipient.
3. **Decrypt** as one of them, then press *"Try to decrypt the other variant"*. It
   refuses with an AES-GCM tag failure. That is the whole argument: the fingerprint is
   not something the recipient's software chose to apply, and there is no unmarked copy
   anywhere in the system to patch your way to.
4. **Trace** the copy back. The report gives a provable bound on the false-accusation
   probability plus five independent corroboration checks — and it will not call itself
   conclusive unless all five hold.
5. **Collude**: splice three recipients' copies together and watch a real colluder
   surface anyway.
6. **Audit**, then corrupt an entry and watch the chain and the witnessed Merkle root
   both refuse to reproduce.

## Deliberate limits, stated up front

The text carrier does **not** survive whitespace normalisation, retyping, OCR, or having
a word inserted or deleted — the declared threat model is redistribution of the file, a
screenshot or a print, not manual reconstruction. When an attack wins, the result is a
*failure to identify*, never a misidentification.

The distributor knows every codeword, so the guarantee is **traceability**, not
**unframeability**; asymmetric fingerprinting would need a post-quantum Paillier
substitute that does not yet exist.

Every one of these is measured in the project's evaluation harness, including the
attacks that win.

## Notes on this deployment

Sessions are per-browser and evicted after three hours; documents are capped at 40 KB
and recipients at 30, so a public demo cannot be made to fill the disk. The container
makes no outbound network calls — the whole design is offline, and this page is a viewer
for it rather than something it depends on.

All sample content is synthetic. There is no real data of any kind in this project.
