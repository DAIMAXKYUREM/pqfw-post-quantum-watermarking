"""Symmetric Tardos fingerprinting codes.

This is the module that turns "these bits came out of the leaked file" into "recipient
7, with a false-accusation probability below 1e-9". It is the mathematically
load-bearing part of PQFW and the only part where a sign error is invisible: swap g0
and g1 and the system still builds packages, still decrypts, still verifies its
ledger, and confidently accuses innocent people.

Construction
------------
Each of the m slots gets a bias p_i drawn from a truncated arcsine distribution.
Recipient j's codeword bit at slot i is Bernoulli(p_i), drawn independently per
recipient. The distributor keeps (p, X); the recipient never learns either.

Accusation (Skoric symmetric score)
-----------------------------------
With g1_i = sqrt((1 - p_i) / p_i) and g0_i = sqrt(p_i / (1 - p_i)), slot i contributes
to recipient j's score:

    y_i  X[j,i]   contribution
    1    1        +g1_i
    1    0        -g0_i
    0    0        +g0_i
    0    1        -g1_i
    None any       0

The construction is chosen so that for an *innocent* recipient each contribution has
mean zero and variance one, whatever p_i is:

    E[contribution] = p*g1 - (1-p)*g0 = sqrt(p(1-p)) - sqrt(p(1-p)) = 0
    Var[contribution] = p*g1^2 + (1-p)*g0^2 = (1-p) + p = 1

so Z_j is approximately N(0, m_eff) over the readable slots and the p-value below is a
real number rather than a decoration. ``test_innocent_score_is_standard_normal_per_slot``
checks that empirically rather than trusting the algebra.

No randomness is drawn here without an injected numpy Generator: the evaluation
harness has to be reproducible.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Sequence

import numpy as np

ERASURE = None
"""A slot whose bit could not be read out of the leaked copy. Not a guess of 0."""


@dataclass(frozen=True)
class TardosParams:
    m: int
    """Code length -- the number of mark slots in the document."""
    n: int
    """Number of enrolled recipients."""
    c: int
    """Largest coalition the code length was chosen for."""
    eps1: float
    """Target false-accusation probability the code length was chosen for."""

    def __post_init__(self) -> None:
        if self.m < 1:
            raise ValueError("code length m must be positive")
        if self.n < 1:
            raise ValueError("there must be at least one recipient")
        if self.c < 1:
            raise ValueError("coalition size c must be positive")
        if not 0.0 < self.eps1 < 1.0:
            raise ValueError("eps1 must be a probability in (0, 1)")

    def to_json(self) -> dict[str, float | int]:
        return {"m": self.m, "n": self.n, "c": self.c, "eps1": self.eps1}

    @staticmethod
    def from_json(obj: dict[str, float | int]) -> "TardosParams":
        return TardosParams(
            m=int(obj["m"]), n=int(obj["n"]), c=int(obj["c"]), eps1=float(obj["eps1"])
        )


@dataclass(frozen=True)
class TardosCode:
    params: TardosParams
    p: np.ndarray
    """Shape (m,). Bias per slot. Secret: never leaves the distributor."""
    X: np.ndarray
    """Shape (n, m), uint8. Codewords. Secret: never leaves the distributor."""

    def codeword(self, recipient_index: int) -> np.ndarray:
        return self.X[recipient_index]

    def duplicate_groups(self) -> list[list[int]]:
        """Recipients who were issued byte-identical codewords.

        Two such recipients receive byte-identical documents and are indistinguishable
        for ever: no amount of evidence separates them, because there is no evidence to
        separate. This is the one tracing failure that produces no symptom at trace
        time -- the score is simply tied -- so it is caught at issue time instead.
        """
        seen: dict[bytes, list[int]] = {}
        for j in range(self.params.n):
            seen.setdefault(self.X[j].tobytes(), []).append(j)
        return [group for group in seen.values() if len(group) > 1]

    def __repr__(self) -> str:
        # Never print p or X. A traced accusation is only credible if the codewords
        # were not lying around in a log file.
        return f"TardosCode(m={self.params.m}, n={self.params.n}, c={self.params.c})"


@dataclass(frozen=True)
class Accusation:
    recipient_index: int
    raw_score: float
    """Z_j, the summed symmetric score."""
    z_score: float
    """Z_j / sqrt(m_eff): standard deviations above an innocent recipient."""
    p_value: float
    """Bonferroni-corrected probability that an innocent recipient scores this high."""
    log10_p_value: float
    """Carried separately because a strong trace underflows p_value to 0.0."""
    m_eff: int
    """Readable slots. The evidence is only as strong as this is large."""

    def to_json(self) -> dict[str, float | int]:
        return {
            "recipient_index": self.recipient_index,
            "raw_score": self.raw_score,
            "z_score": self.z_score,
            "p_value": self.p_value,
            "log10_p_value": self.log10_p_value,
            "m_eff": self.m_eff,
        }


# ---------------------------------------------------------------------------
# code construction
# ---------------------------------------------------------------------------


def code_length(c: int, eps1: float, constant: float = 100.0) -> int:
    """m = constant * c^2 * ln(1 / eps1).

    The classical Tardos constant is 100. The symmetric score used here is provably
    fine at pi^2 ~ 9.87, and in practice a much shorter code still gives an *honest*
    answer -- just a weaker one, because the p-value is computed from the score that
    was actually observed rather than promised in advance. The evaluation harness
    sweeps the constant; the CLI lets a document's slot capacity cap it.
    """
    if c < 1:
        raise ValueError("coalition size c must be positive")
    if not 0.0 < eps1 < 1.0:
        raise ValueError("eps1 must be a probability in (0, 1)")
    return int(math.ceil(constant * c * c * math.log(1.0 / eps1)))


def generate(
    params: TardosParams,
    rng: np.random.Generator,
    ensure_distinct: bool = True,
    max_passes: int = 64,
) -> TardosCode:
    """Draw the biases and every recipient's codeword.

    ``ensure_distinct`` redraws any recipient who happens to collide with an earlier
    one. The arcsine biases sit close to 0 and 1 by design, so codewords agree far
    more often than uniform coin flips would, and with a short code two recipients
    colliding is not a curiosity -- it is a permanent hole in the audit trail.

    Resampling only the colliding rows conditions the code on distinctness. When
    collisions are rare, which is the regime any usable code length puts you in, the
    effect on the score distribution is negligible; when they are common the code was
    already too short to trace with, and this raises instead of pretending otherwise.
    """
    t = 1.0 / (300 * params.c)
    t_prime = math.asin(math.sqrt(t))
    r = rng.uniform(t_prime, math.pi / 2 - t_prime, size=params.m)
    p = np.sin(r) ** 2

    X = (rng.random((params.n, params.m)) < p).astype(np.uint8)
    code = TardosCode(params=params, p=p, X=X)
    if not ensure_distinct:
        return code

    for _ in range(max_passes):
        duplicates = [j for group in code.duplicate_groups() for j in group[1:]]
        if not duplicates:
            return code
        X[duplicates] = (rng.random((len(duplicates), params.m)) < p).astype(np.uint8)
    raise ValueError(
        f"could not issue {params.n} distinct codewords in {params.m} slots after "
        f"{max_passes} passes: the code is too short for this many recipients. "
        f"Increase m (see code_length) or reduce n."
    )


# ---------------------------------------------------------------------------
# extracted-bit handling
# ---------------------------------------------------------------------------


def as_y(bits: Sequence[int | None] | np.ndarray, m: int) -> np.ndarray:
    """Normalise extracted bits to a float array using NaN for an erasure.

    Erasures are kept distinct from zeros all the way through. Reading an unreadable
    slot as 0 would push half the coalition's members towards a negative score and the
    other half towards a positive one, for no reason at all.
    """
    arr = np.asarray(bits, dtype=object).reshape(-1)
    if arr.shape[0] != m:
        raise ValueError(f"extracted bit vector has length {arr.shape[0]}, expected {m}")
    out = np.empty(m, dtype=np.float64)
    for i, b in enumerate(arr):
        if b is None or (isinstance(b, float) and math.isnan(b)):
            out[i] = math.nan
        else:
            ib = int(b)
            if ib not in (0, 1):
                raise ValueError(f"slot {i}: extracted bit must be 0, 1 or None, got {b!r}")
            out[i] = float(ib)
    return out


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


def scores(code: TardosCode, y: Sequence[int | None] | np.ndarray) -> np.ndarray:
    """Symmetric Tardos score for every recipient. Shape (n,).

    Vectorised: one (n, m) x (m,) matrix-vector product, no Python loop over n * m.
    """
    yv = as_y(y, code.params.m)
    readable = ~np.isnan(yv)

    p = code.p
    g1 = np.sqrt((1.0 - p) / p)
    g0 = np.sqrt(p / (1.0 - p))

    # Per-slot contribution if y_i were 1, for each recipient:
    #   X == 1 -> +g1, X == 0 -> -g0.
    # For y_i == 0 the whole column flips sign, which is exactly the table in the
    # module docstring, so a single signed weight vector covers both cases.
    contribution_if_one = code.X * g1 - (1 - code.X) * g0

    sign = np.zeros(code.params.m, dtype=np.float64)
    sign[readable] = np.where(yv[readable] == 1.0, 1.0, -1.0)

    return contribution_if_one @ sign


def readable_count(y: Sequence[int | None] | np.ndarray, m: int) -> int:
    return int(np.count_nonzero(~np.isnan(as_y(y, m))))


def _sf(z: float) -> float:
    """Upper tail of the standard normal: 1 - Phi(z)."""
    return 0.5 * math.erfc(z / math.sqrt(2.0))


def _log10_sf(z: float) -> float:
    """log10 of the upper tail, valid past the point where erfc underflows.

    For large z, 1 - Phi(z) ~ exp(-z^2/2) / (z * sqrt(2*pi)) * (1 - 1/z^2 + 3/z^4),
    which stays finite in log space long after the probability itself is 0.0 in
    double precision.
    """
    tail = _sf(z)
    if tail > 0.0:
        return math.log10(tail)
    ln_tail = -0.5 * z * z - math.log(z * math.sqrt(2.0 * math.pi))
    ln_tail += math.log1p(-1.0 / (z * z) + 3.0 / (z**4))
    return ln_tail / math.log(10.0)


def p_value_for_z(z: float, n: int) -> float:
    """Bonferroni-corrected tail probability, clamped to a probability.

    The correction is over all n enrolled recipients because tracing takes the maximum
    score over all of them. Quoting an uncorrected tail would overstate the evidence
    by a factor of n, and n is the one number the defence will check.
    """
    return min(1.0, max(0.0, n * _sf(z)))


def log10_p_value_for_z(z: float, n: int) -> float:
    if z <= 0.0:
        return 0.0
    return min(0.0, math.log10(n) + _log10_sf(z))


def rank(code: TardosCode, y: Sequence[int | None] | np.ndarray) -> list[Accusation]:
    """Every recipient scored and sorted, most suspicious first.

    Tracing reports the runners-up alongside the accused: a top score that is barely
    above the second is a different kind of evidence from one that is ten sigma clear,
    and hiding that would be dishonest.
    """
    raw = scores(code, y)
    m_eff = readable_count(y, code.params.m)
    n = code.params.n

    out: list[Accusation] = []
    for j in range(n):
        raw_j = float(raw[j])
        if m_eff == 0:
            z = 0.0
            pv, log10_pv = 1.0, 0.0
        else:
            z = raw_j / math.sqrt(m_eff)
            pv = p_value_for_z(z, n)
            log10_pv = log10_p_value_for_z(z, n)
        out.append(
            Accusation(
                recipient_index=j,
                raw_score=raw_j,
                z_score=z,
                p_value=pv,
                log10_p_value=log10_pv,
                m_eff=m_eff,
            )
        )
    out.sort(key=lambda a: a.raw_score, reverse=True)
    return out


def accuse(
    code: TardosCode, y: Sequence[int | None] | np.ndarray, alpha: float = 1e-6
) -> list[Accusation]:
    """Only the recipients whose corrected p-value clears alpha, strongest first.

    An empty list is a legitimate and common answer. It means the leaked copy does not
    carry enough evidence to name anybody at the confidence asked for -- not that the
    document was never fingerprinted.
    """
    return [a for a in rank(code, y) if a.p_value < alpha]


# ---------------------------------------------------------------------------
# collusion strategies (evaluation only)
# ---------------------------------------------------------------------------

STRATEGIES = ("majority", "minority", "interleaving", "coinflip", "all_ones", "all_zeros")


def collude(
    codewords: np.ndarray, strategy: str, rng: np.random.Generator
) -> np.ndarray:
    """Forge a y from a coalition's codewords.

    Every strategy here obeys the marking assumption: where all colluders agree, they
    cannot produce the opposite bit, because none of them holds the key that decrypts
    the other variant. That is not an assumption we ask the attacker to respect -- it
    is enforced by ``package.py``.
    """
    if codewords.ndim != 2 or codewords.shape[0] < 1:
        raise ValueError("codewords must be a (coalition_size, m) array")
    size, m = codewords.shape

    if strategy == "majority":
        y = (codewords.mean(axis=0) > 0.5).astype(np.uint8)
        ties = np.isclose(codewords.mean(axis=0), 0.5)
        y[ties] = (rng.random(int(ties.sum())) < 0.5).astype(np.uint8)
        return y
    if strategy == "minority":
        y = (codewords.mean(axis=0) < 0.5).astype(np.uint8)
        agreed = (codewords.min(axis=0) == codewords.max(axis=0))
        y[agreed] = codewords[0][agreed]  # forced by the marking assumption
        return y
    if strategy == "interleaving":
        picks = rng.integers(0, size, size=m)
        return codewords[picks, np.arange(m)].astype(np.uint8)
    if strategy == "coinflip":
        y = (rng.random(m) < 0.5).astype(np.uint8)
        agreed = (codewords.min(axis=0) == codewords.max(axis=0))
        y[agreed] = codewords[0][agreed]
        return y
    if strategy == "all_ones":
        y = np.ones(m, dtype=np.uint8)
        agreed = (codewords.min(axis=0) == codewords.max(axis=0))
        y[agreed] = codewords[0][agreed]
        return y
    if strategy == "all_zeros":
        y = np.zeros(m, dtype=np.uint8)
        agreed = (codewords.min(axis=0) == codewords.max(axis=0))
        y[agreed] = codewords[0][agreed]
        return y
    raise ValueError(f"unknown collusion strategy {strategy!r}; expected one of {STRATEGIES}")


def erase(
    y: np.ndarray | Sequence[int | None], fraction: float, rng: np.random.Generator
) -> list[int | None]:
    """Knock out a fraction of the slots, as truncation or reformatting would."""
    out: list[int | None] = [None if b is None else int(b) for b in _as_list(y)]
    k = int(round(fraction * len(out)))
    if k <= 0:
        return out
    for i in rng.choice(len(out), size=min(k, len(out)), replace=False):
        out[int(i)] = None
    return out


def _as_list(y: np.ndarray | Iterable[int | None]) -> list[int | None]:
    if isinstance(y, np.ndarray):
        return [None if isinstance(v, float) and math.isnan(v) else int(v) for v in y.tolist()]
    return list(y)
