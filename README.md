# PQFW — Post-Quantum Forensic Watermarking

A document is encrypted **once** for N recipients. Each recipient's decryption produces
a visually identical but **uniquely fingerprinted** copy. The fingerprint is enforced by
**which keys they hold**, not by client-side software that politely applies a watermark.
A leaked copy traces back to a recipient with a **provable** false-accusation
probability, corroborated by a tamper-evident append-only ledger.

Everything runs offline. No cloud KMS, no timestamping service, no public chain, no
network calls at runtime — asserted by [`tests/test_offline.py`](tests/test_offline.py),
which replaces the socket layer with one that refuses every operation and then runs the
whole pipeline anyway.

```bash
pqfw enroll  --recipients 20 --out ./state
pqfw protect --doc report.txt --state ./state --coalition 3 --eps 1e-6
pqfw open    --doc-id report --recipient r07 --state ./state --out leaked.txt
pqfw trace   --doc-id report --leaked leaked.txt --state ./state
pqfw audit   --state ./state --tamper 0
```

---

## Why this is not a watermark

Ordinary forensic watermarking asks the recipient's software to add a mark. A recipient
who patches the viewer gets a clean copy, and there is nothing in the cryptography to
stop them.

PQFW splits the document into a base body plus `m` **mark slots**. Each slot is rendered
two ways that a reader cannot tell apart, and the two renderings are encrypted under
**different** keys. Both ship to everybody. A recipient's key bundle holds exactly
**one** variant key per slot, chosen by their Tardos codeword bit, so the other
rendering is an AES-GCM tag failure for them:

```
slot i   variant 0  ──encrypted under VK[i][0]──┐
         variant 1  ──encrypted under VK[i][1]──┤── both in the shared ciphertext
                                                 │
recipient j's bundle:  VK[i][ X[j][i] ]  ← one of the two, never both
```

There is no code path around a tag check. Patching the client does not help; reverse
engineering it does not help. **There is no unmarked copy anywhere in the system** — not
in the package, not in transit, not on the distributor's disk after `build_package`
returns. The fingerprint is a consequence of key possession, and
[`test_recipient_cannot_decrypt_the_other_variant`](tests/test_package.py) is the test
that says so.

The cost of this is one shared ciphertext plus a small per-recipient envelope:

| | size | scales with |
|---|---|---|
| shared ciphertext | 116 KB at m=800 | document + m, **identical for all recipients** |
| per-recipient envelope | 34 KB at m=800 | m only — **independent of N and of document size** |

## Cryptography

| Purpose | Primitive |
|---|---|
| Key-bundle wrapping | **ML-KEM-768** (FIPS 203) |
| Decryption receipts, witness signatures | **ML-DSA-65** (FIPS 204) |
| Base segments and slot variants | AES-256-GCM, AAD-bound to `(doc_id, slot, variant)` |
| KDF, hash chain, Merkle tree, commitments | SHA3-256 / HKDF-SHA3-256 |
| Fingerprint code | Symmetric (Škorić) Tardos code |

PQC binding: **`liboqs-python` 0.16.0**, which builds liboqs 0.16.0 natively.
`tests/test_env.py` asserts both mechanisms are present and is the gate for every other
test. No RSA or Ed25519 fallback exists — post-quantum is the premise, not an option.

---

## The number the system stands behind

A trace never reports a bare identification. It reports a false-accusation probability,
and the one it gates on is a **provable Chernoff bound**, not a Gaussian p-value.

That distinction came out of the evaluation harness rather than out of theory. The
Tardos score is a sum of `m` independent terms each with mean 0 and variance 1 — but not
each *small*: a slot whose bias sits near the truncation limit contributes up to 27,
while the whole sum's standard deviation at m=800 is 28. A handful of slots dominate,
the central limit theorem has not taken hold in the tail, and **the normal approximation
understates the false-accusation rate**:

| nominal α | empirical rate, Gaussian p-value | empirical rate, provable bound |
|---|---|---|
| 1e-3 | 2.4e-3 — **above nominal** | 1.6e-3 |
| 1e-4 | 5.0e-4 — **above nominal** | 1.0e-4 |
| 1e-5 … 1e-9 | 0 / 10,000 | 0 / 10,000 |

So the bound is computed instead, with the exact per-slot moment generating function
and no asymptotic step anywhere:

```
P(Z ≥ t) ≤ min over λ>0 of  exp(−λt) · Π_i E[exp(λ·w_i)]
```

Valid because an innocent recipient's codeword is independent of the extracted bits —
they hold no key that could have influenced them. And because the score is *bounded*,
the bound is not merely valid but **tighter** than the Gaussian tail in the regime an
accusation actually lives in: at m=301 a real leaker's bound comes out near 1e-47 where
the Gaussian says 1e-25. Using the rigorous number costs nothing.

The Gaussian p-value is still reported, beside the bound, for comparison.

### A trace is not conclusive on statistics alone

`TraceReport.conclusive` requires all five of:

1. the provable bound clears α,
2. the accused's own **ML-DSA-65 receipt** verifies — they signed for this copy,
3. the ledger **hash chain** is intact,
4. a **k-of-n witness checkpoint** covers that entry,
5. a **Merkle inclusion proof** ties it to the witness-signed root.

Statistics alone gives a suspect. Conditions 2–5 say the codeword was issued to someone
who signed for it and that the record has not been touched since. A trace that clears
the statistics but fails the ledger checks reports `UNCORROBORATED` — a lead, not an
identification. That is how an innocent person avoids being named.

---

## Threat model

**In scope.** Redistribution of the artefact: the file itself, forwarded, re-uploaded,
attached, archived, screenshotted, or printed. Collusion between recipients who pool
their copies. A dishonest administrator who edits, deletes, reorders or wholesale
rewrites the ledger.

**Out of scope, and why.**

- **Retyping and OCR.** No text carrier survives a human reading the document and typing
  it out. Measured, reported, not worked around.
- **Unframeability.** The distributor knows every codeword, so the guarantee is
  **traceability**, not unframeability — a malicious distributor could in principle
  fabricate a copy carrying someone's marks. True non-repudiation needs asymmetric
  fingerprinting (classically Paillier plus zero-knowledge proofs), and there is no
  drop-in post-quantum Paillier. A BFV-based construction is the documented next step;
  it is not built here and is not claimed.
- **A compromised recipient device.** Someone who leaks their own private key leaks
  their own accountability. Out of scope for any scheme of this shape.
- **Sealed-store key custody.** The store is AES-256-GCM encrypted at rest under
  `seal.key`, which sits next to it. That protects against a stray copy — a backup, a
  repo commit, a support bundle — and not at all against an attacker who can read the
  directory. A deployment puts that key in an HSM or derives it from an operator
  passphrase; the interface does not change when it does.

---

## Attacks that defeat the carrier

Measured, with the wins and the losses both reported
([`eval/results/attacks.csv`](eval/results/attacks.csv),
[fig4](eval/results/fig4_attacks.png)). Text carrier, m=728:

| attack | bit error rate | outcome |
|---|---|---|
| baseline | 0% | traced, z=19.0 |
| Unicode NFC / NFKC normalisation | 0% | traced |
| re-encode via UTF-16 and back | 0% | traced |
| truncate to 75% / 50% / 25% | 0% | traced (z=16.5 / 13.8 / 10.1) |
| collapse runs of spaces and tabs | 0% | traced — U+200B is a *format* character, not whitespace, so `\s+` does not touch it |
| **strip all Unicode format characters** | **51%** | **defeats it** |
| **retype the document** | **51%** | **defeats it** |
| **prepend one word** | **51%** | **defeats it** — desynchronisation |
| insert one word halfway | 25% | traced (the head still lines up) |
| **delete the first word** | **51%** | **defeats it** — desynchronisation |

Two things worth being explicit about:

**Truncation is survivable, rewriting is not.** Cutting the document only *removes*
slots, and a removed slot is carried as an erasure rather than guessed as a zero — so
the evidence weakens and never inverts. Across a 0–95% erasure sweep, misidentification
stays at **0.0%** at every level ([fig3](eval/results/fig3_erasure.png)).

**Ordinal locators do not resynchronise.** A slot's address is "the k-th space in the
document", so inserting or deleting a word shifts every later address and the extractor
reads neighbouring slots. This is the sharpest limitation of the design and the first
thing anyone asks about. A content-anchored locator — landmarks derived from a rolling
hash of surrounding words — would fix it and is the natural next iteration.

When an attack wins, the result is a **failure to identify**, never a misidentification.

---

## Collusion resistance

Coalitions can only act where their members disagree; where they agree they are stuck,
because none of them holds the key for the other rendering. That constraint is
*enforced* by `package.py`, not assumed of the attacker
([`test_a_coalition_still_cannot_forge_a_slot_they_agree_on`](tests/test_package.py)).

200 trials per cell, five strategies (majority, minority, interleaving, coin-flip,
all-ones), n=100 ([fig1](eval/results/fig1_coalition.png)):

| coalition | detection at m=1200 | detection at the prescribed m = 100c²ln(1/ε) | mean rank of first colluder |
|---|---|---|---|
| 1 | 100% | 100% | 1.00 |
| 2 | 100% | 100% | 1.00 |
| 3 | 100% | 100% | 1.00 |
| 5 | 45–57% | **100%** | 1.00 |
| 8 | 0.5–8% | **100%** | 1.00–1.30 |

The pair of columns is the interesting result. At a code length a real document can hold,
detection against a large coalition collapses — while the mean rank of the first true
colluder stays at 1.0 and innocent accusations stay at **0.0%**. The ordering barely
degrades; what degrades is *confidence*. A short code costs confidence, not correctness,
and the system declines to name anybody rather than guessing.

`pqfw protect` says this up front: it reports the code length the Tardos bound asks for,
the length the document can hold, and the best false-accusation probability actually
reachable — before anything is distributed.

---

## The ledger

Every decryption appends an ML-DSA-65-signed receipt to a hash chain. Merkle checkpoints
over the chain are signed by k of n independent witness keys (default 2-of-3), and the
root is exported as a **QR code** — print it and the paper is a witness. A ledger
rewritten later cannot match a root published before it was rewritten, and that needs no
chain, no orderer and no network.

**The ledger contains no codewords.** A receipt carries `SHA3-256(codeword ‖ salt)` and
nothing else about the fingerprint, so the ledger could be published in full — handed to
every recipient, printed, pinned to a wall — without giving anybody the means to forge,
strip or transplant a mark. The pre-images stay in the distributor's sealed store.

Four kinds of history rewriting, all detected and *located*: editing a record, deleting
an entry, reordering entries, forging a checkpoint. Editing a record and then recomputing
every downstream hash still fails, because the administrator cannot reproduce the
recipient's signature. Truncating the *tail* leaves a valid chain — the known limit of a
hash chain, and exactly why checkpoints exist: the witnessed root no longer reproduces.

```bash
pqfw audit --state ./state --tamper 0    # corrupt an entry, watch it get caught
pqfw audit --state ./state --restore     # put it back, so the demo runs twice
```

> On "blockchain": a hash chain plus k-of-n independent witnesses gives strictly better
> single-administrator resistance in an air gap than a single-orderer Fabric network. If
> a requirement forces the word, a Fabric or CometBFT backend goes behind the same
> `Ledger` interface — a swap, not a rewrite.

---

## Carriers

| | text-zwsp | pdf-kern |
|---|---|---|
| slot | one inter-word space | one inter-word kern in a `TJ` array |
| variant 0 | `U+0020` | `+4.0` (tighten 4/1000 em) |
| variant 1 | `U+0020 U+200B` | `-4.0` (loosen 4/1000 em) |
| capacity | one per space | one per inter-word gap |
| survives | byte-preserving redistribution | normalising re-save, recompression |

Both variants of the PDF kern are **four bytes**, so every xref offset and stream
`/Length` stays correct whichever variant is chosen — which is what lets a PDF pass
through a byte-splicing carrier at all, and why the crypto layer never learns it is
handling a PDF. Extraction parses the content stream rather than searching bytes, so a
re-saved and recompressed copy is still readable.

The PDF mark measures as: 0.088 pt between variants, **2.9% of the width of a space**,
against the 10–50% variation ordinary justification introduces. Total ink on the page is
identical to within 0.01% — glyphs move, none appear, vanish or change weight. Worst-case
accumulated end-of-line drift is 0.62 pt (under a third of a millimetre); the variants
are centred on zero rather than being `(0, −8)` precisely so that drift is a mean-zero
random walk instead of a monotone sum.

It does **not** mean two copies are pixel-identical: diff two rasterised copies and ~4%
of pixels differ at glyph edges. Anyone holding two copies can see *which* slots
disagree. That is true of every fingerprinting scheme, and it is the attack the Tardos
code exists to survive — knowing where copies differ does not tell a coalition what to
put there.

PDF scope: **sender-generated documents only.** PQFW types the document, so it controls
the typesetting. Retrofitting slots into an arbitrary uploaded PDF is a different and
much harder problem and is not attempted.

---

## Layout

```
src/pqfw/
  pqc.py            ML-KEM-768 / ML-DSA-65 / AES-256-GCM / HKDF wrappers
  tardos.py         code generation, symmetric scoring, the provable tail bound
  carrier.py        MarkCarrier protocol
  carriers/text.py  zero-width-space carrier
  carriers/pdf.py   PDF kerning carrier
  package.py        variant-keyed broadcast encryption  ← the core novelty
  ledger.py         hash chain + k-of-n witness-signed Merkle checkpoints + QR anchor
  store.py          sealed distributor store / recipient devices / public ledger
  trace.py          extraction → accusation → ledger verification
  workflow.py       the five operations, as functions
  cli.py            enroll / protect / open / trace / audit
web/                FastAPI demo over the real library
eval/run_eval.py    evaluation harness and attack suite
eval/results/       CSVs and figures, committed
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv/Scripts/activate
pip install -e ".[dev,web]"
pytest -q                                            # 133 tests
python eval/run_eval.py                              # full evaluation, a few minutes
python -m uvicorn app:app --app-dir web --port 7860  # the browser demo
```

## Reproducibility

No library code calls `datetime.now()` or draws randomness without an injected clock or
`numpy.random.Generator`. Everything hashed or signed goes through one canonical JSON
serialiser. The evaluation harness is seeded, the seeds are in the CSVs, and the batched
scorer it uses for Monte-Carlo work is checked against the reference scorer before any
experiment runs — so the fast path cannot drift from the code that produces real
accusations.

## No real victim data

Every document in this repository, in the tests, in the evaluation harness and in the
demo is synthetic.
