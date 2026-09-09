---
title: PQFW — Post-Quantum Forensic Watermarking
emoji: 🔏
colorFrom: indigo
colorTo: gray
sdk: static
app_file: index.html
pinned: false
license: mit
short_description: One encryption, N fingerprints, enforced by key possession
---

# PQFW — Post-Quantum Forensic Watermarking

A document is encrypted **once** for N recipients. Each recipient's decryption produces
a visually identical but **uniquely fingerprinted** copy — and the fingerprint is
enforced by **which keys they hold**, not by software that politely applies a watermark.
A leaked copy traces back to a recipient with a **provable** false-accusation
probability, corroborated by a tamper-evident append-only ledger.

**ML-KEM-768** (FIPS 203) wraps each recipient's key bundle. **ML-DSA-65** (FIPS 204)
signs their decryption receipt. AES-256-GCM encrypts the slot variants, and the tag
check is what makes the fingerprint unavoidable.

## What this page is

Every figure, table and transcript here was produced by **executing the real library**,
and the commit and timestamp are recorded at the top of the page. It is a *recorded*
run, not a live one, and it says so throughout.

The interactive version needs a server — the point of the project is that liboqs does
the work, so reimplementing ML-KEM and the Tardos scorer in JavaScript to fit a static
host would replace the thing being demonstrated with an untested copy of it. Hugging
Face keeps static Spaces free for everyone but now requires PRO for Spaces that run a
server, so the interactive demo ships as a container instead (`deploy/Dockerfile`, with
a Render blueprint alongside it).

## Findings worth reading before the code

- The **Gaussian p-value is not conservative** for a Tardos score at these code lengths:
  a handful of extreme-bias slots dominate the sum and the tail is heavier than normal.
  Measured at 2.4e-3 against a nominal 1e-3. Accusations therefore gate on a provable
  Chernoff bound computed from the code's own biases — which, because the score is
  bounded, turns out to be *tighter* than the Gaussian in the regime that matters.
- **Truncation is survivable; rewriting is not.** Cutting a document only removes slots,
  and a removed slot is carried as an erasure rather than guessed as a zero. Across a
  0–95% erasure sweep, misidentification stays at 0.0% at every level.
- **A short code costs confidence, not correctness.** Against a coalition of eight at a
  code length a real document can hold, detection collapses — while the true colluder
  stays ranked first and innocent accusations stay at 0.0%. The system declines to name
  anybody rather than guessing.
- The attacks that **defeat** the carrier are listed with their measured bit error
  rates, next to the ones it survives.

All sample content is synthetic. There is no real data of any kind in this project.
