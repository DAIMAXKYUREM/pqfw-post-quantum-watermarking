# PQFW — Post-Quantum Forensic Watermarking

An offline system where a document is encrypted **once** for N recipients, each
recipient's decryption produces a **visually identical but uniquely fingerprinted**
copy, the fingerprint is enforced by **key possession** rather than by client-side
software, and a leaked copy is traced back to a recipient with a **stated
false-accusation probability**, backed by a tamper-evident append-only ledger.

## Why this is not just a watermark

Ordinary forensic watermarking asks the recipient's software to please add a mark.
A recipient who patches the viewer gets a clean copy.

PQFW splits the document into a base body plus `m` *mark slots*. Each slot is
rendered as two visually equivalent variants and each variant is encrypted under a
**different** variant key. A recipient's key bundle contains exactly **one** variant
key per slot, chosen by their Tardos codeword bit. They therefore *cannot* decrypt
the other variant — the AEAD tag check fails. The fingerprint is a consequence of
which keys they hold, not a decision their software made.

## Cryptography

| Purpose | Primitive |
|---|---|
| Key bundle wrapping | **ML-KEM-768** (FIPS 203) |
| Decryption receipts, witness signatures | **ML-DSA-65** (FIPS 204) |
| Content / variant encryption | AES-256-GCM |
| KDF, hash chain, Merkle tree, commitments | SHA3-256 / HKDF-SHA3-256 |
| Fingerprint code | Symmetric (Škorić) Tardos code |

No network calls at runtime. No cloud KMS. No public chain.

## PQC binding used

`liboqs-python` **0.16.0**, which builds and installs liboqs 0.16.0 natively on first
import (`~/_oqs`). Verified mechanisms: `ML-KEM-768` in the KEM list, `ML-DSA-65` in
the signature list — asserted by `tests/test_env.py`, which is the gate for every
other test.

## Layout

```
src/pqfw/
  pqc.py            ML-KEM-768 / ML-DSA-65 / AES-256-GCM wrappers
  tardos.py         codeword generation and symmetric accusation scoring
  carrier.py        MarkCarrier protocol
  carriers/text.py  zero-width-space text carrier
  carriers/pdf.py   PDF kerning carrier
  package.py        variant-keyed broadcast encryption
  ledger.py         hash chain + k-of-n witness-signed Merkle checkpoints
  trace.py          extraction -> accusation -> ledger verification
  cli.py            enroll / protect / open / trace / audit
eval/run_eval.py    attack suite and figures
```

## Setup

```bash
python -m venv .venv && source .venv/Scripts/activate   # Windows: .venv/Scripts/activate
pip install -e ".[dev,web]"
pytest -q
```
