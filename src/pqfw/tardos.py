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
    """Gaussian-approximation tail probability, Bonferroni-corrected over n.

    Reported for reference and comparison. **Not** the number to rely on: the
    evaluation harness shows it understates the true rate at loose thresholds,
    because a few extreme-bias slots dominate the sum and the central limit theorem
    has not taken hold in the tail. See ``chernoff_log10_bound``.
    """
    log10_p_value: float
    """Carried separately because a strong trace underflows p_value to 0.0."""
    p_bound: float
    """Provable upper bound on the false-accusation probability. This is the number
    the system stands behind, and the one ``accuse`` gates on."""
    log10_p_bound: float
    p_bound_exact: bool
    """False when the bound was not computed for this recipient because a
    higher-scoring one already failed the gate -- the bound is monotone in the score,
    so everyone below is provably no more accusable. 1.0 means "not accusable", not
    "certainly innocent"."""
    m_eff: int
    """Readable slots. The evidence is only as strong as this is large."""

    def to_json(self) -> dict[str, float | int | bool]:
        return {
            "recipient_index": self.recipient_index,
            "raw_score": self.raw_score,
            "z_score": self.z_score,
            "p_value": self.p_value,
            "log10_p_value": self.log10_p_value,
            "p_bound": self.p_bound,
            "log10_p_bound": self.log10_p_bound,
            "p_bound_exact": self.p_bound_exact,
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
    if isinstance(bits, np.ndarray) and bits.dtype != object:
        # Fast path. The object loop below is O(m) in Python, and scoring a leak used
        # to walk it once per recipient.
        flat = bits.reshape(-1)
        if flat.shape[0] != m:
            raise ValueError(f"extracted bit vector has length {flat.shape[0]}, expected {m}")
        out = flat.astype(np.float64)
        finite = ~np.isnan(out)
        if not np.isin(out[finite], (0.0, 1.0)).all():
            raise ValueError("extracted bits must be 0, 1 or NaN")
        return out

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


def sign_vector(yv: np.ndarray) -> np.ndarray:
    """+1 where the extracted bit is 1, -1 where it is 0, 0 where it is unreadable."""
    readable = ~np.isnan(yv)
    sign = np.zeros(yv.shape[0], dtype=np.float64)
    sign[readable] = np.where(yv[readable] == 1.0, 1.0, -1.0)
    return sign


def _scores_from_sign(code: TardosCode, sign: np.ndarray) -> np.ndarray:
    p = code.p
    g1 = np.sqrt((1.0 - p) / p)
    g0 = np.sqrt(p / (1.0 - p))

    # Per-slot contribution if y_i were 1, for each recipient:
    #   X == 1 -> +g1, X == 0 -> -g0.
    # For y_i == 0 the whole column flips sign, which is exactly the table in the
    # module docstring, so a single signed weight vector covers both cases.
    contribution_if_one = code.X * g1 - (1 - code.X) * g0
    return contribution_if_one @ sign


def scores(code: TardosCode, y: Sequence[int | None] | np.ndarray) -> np.ndarray:
    """Symmetric Tardos score for every recipient. Shape (n,).

    Vectorised: one (n, m) x (m,) matrix-vector product, no Python loop over n * m.
    """
    return _scores_from_sign(code, sign_vector(as_y(y, code.params.m)))


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


class TailBound:
    """Provable Chernoff bound on an innocent recipient's score, for one leak.

    Why this exists, when there is already a Gaussian p-value
    --------------------------------------------------------
    The score is a sum of m independent terms, each with mean 0 and variance 1 -- but
    not each *small*. A slot whose bias sits near the truncation limit t = 1/(300c)
    has g1 = sqrt((1-p)/p) of about 27, while the whole sum's standard deviation at
    m = 800 is only 28. A handful of slots therefore dominate the variance, the central
    limit theorem has not taken hold in the tail, and the normal approximation
    *understates* the false-accusation probability. The evaluation harness measures
    this directly: at alpha = 1e-3 the empirical rate is 2.4e-3.

    Since the entire claim of this project is a stated false-accusation probability, an
    optimistic one is worse than none. So the number the system stands behind is a
    Chernoff bound using the exact per-slot moment generating function:

        P(Z >= t) <= min over lambda > 0 of  exp(-lambda*t) * prod_i E[exp(lambda*w_i)]

    Every factor is computed from this code's own biases, exactly, with no asymptotic
    step anywhere. For an innocent recipient X[j] is independent of y -- they hold no
    key that could have influenced it -- so conditioning on y is legitimate, which is
    what makes each per-slot distribution known and the product valid.

    Because the score is bounded, this is not merely valid but *tighter* than the
    Gaussian tail in the regime that matters: at m = 301 a real leaker's bound comes
    out near 1e-47 where the Gaussian approximation says 1e-25.

    The per-slot arrays depend only on (p, y), never on which recipient is being
    scored, so they are built once here and reused for all n.
    """

    __slots__ = ("_hi", "_lo", "_log_prob_hi", "_log_prob_lo", "_m_eff", "_n", "_max_score")

    def __init__(self, code: TardosCode, yv: np.ndarray) -> None:
        readable = ~np.isnan(yv)
        p = code.p[readable]
        sign = np.where(yv[readable] == 1.0, 1.0, -1.0)
        g1 = np.sqrt((1.0 - p) / p)
        g0 = np.sqrt(p / (1.0 - p))

        # Slot i takes value hi with probability p_i, lo with probability 1 - p_i.
        self._hi = sign * g1
        self._lo = -sign * g0
        self._log_prob_hi = np.log(p)
        self._log_prob_lo = np.log1p(-p)
        self._m_eff = int(readable.sum())
        self._n = code.params.n
        self._max_score = float(np.maximum(self._hi, self._lo).sum())

    @property
    def m_eff(self) -> int:
        return self._m_eff

    def _log_tail(self, lam: float, threshold: float) -> float:
        # log-sum-exp per slot, so a lambda*g1 of a few hundred cannot overflow
        a = lam * self._hi + self._log_prob_hi
        b = lam * self._lo + self._log_prob_lo
        peak = np.maximum(a, b)
        log_mgf = peak + np.log(np.exp(a - peak) + np.exp(b - peak))
        return float(-lam * threshold + log_mgf.sum())

    def log10_bound(self, threshold: float, refine: bool = True) -> float:
        """log10 of the bound, Bonferroni-corrected over all n recipients.

        Any single lambda > 0 already yields a *valid* bound, so the cheap path
        evaluates one well-chosen lambda and only pays for the minimisation when the
        answer is close enough to an accusation threshold to be worth tightening. That
        keeps ranking a thousand recipients affordable without ever quoting a number
        the bound does not support.
        """
        if self._m_eff == 0 or threshold <= 0.0:
            return 0.0
        if threshold > self._max_score:
            return -math.inf  # unreachable even if every slot went the same way

        correction = math.log(self._n)
        # For a sum of unit-variance terms the optimal lambda sits near t / variance.
        seed = max(threshold / self._m_eff, 1e-9)
        best = self._log_tail(seed, threshold)
        if not refine:
            return min(0.0, (best + correction) / math.log(10.0))

        # _log_tail is convex in lambda: bracket around the seed, then ternary search.
        lo, hi = seed / 64.0, seed * 64.0
        for _ in range(80):
            a = lo + (hi - lo) / 3.0
            b = hi - (hi - lo) / 3.0
            if self._log_tail(a, threshold) < self._log_tail(b, threshold):
                hi = b
            else:
                lo = a
        best = min(best, self._log_tail((lo + hi) / 2.0, threshold))
        return min(0.0, (best + correction) / math.log(10.0))


def chernoff_log10_bound(
    code: TardosCode,
    y: Sequence[int | None] | np.ndarray,
    threshold: float,
    refine: bool = True,
) -> float:
    """One-shot convenience wrapper around :class:`TailBound`."""
    return TailBound(code, as_y(y, code.params.m)).log10_bound(threshold, refine=refine)


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


def expected_traitor_score(code: TardosCode) -> float:
    """The score a single leaker's own copy is expected to produce.

    For y = X[j], slot i contributes +g1 with probability p_i and +g0 with probability
    1 - p_i, so its expectation is 2*sqrt(p_i (1 - p_i)). Summed over the actual biases
    rather than over their asymptotic mean, because this is used to tell an operator
    what a specific code length can and cannot deliver.
    """
    p = code.p
    return float(np.sum(2.0 * np.sqrt(p * (1.0 - p))))


def achievable_eps(code: TardosCode) -> float:
    """The best false-accusation probability this code length can be expected to reach.

    A document only holds so many slots. When the carrier caps the code below what the
    requested eps1 needs, this is the number that is actually on offer -- reporting it
    up front is the difference between weaker evidence and a surprise at trace time.
    """
    if code.params.m == 0:
        return 1.0
    z = expected_traitor_score(code) / math.sqrt(code.params.m)
    return p_value_for_z(z, code.params.n)


BOUND_GATE = 1e-3
"""Stop computing exact bounds once one exceeds this.

The Chernoff bound is monotone decreasing in the score, so once a recipient's bound
crosses the gate, every lower-scoring recipient's bound is provably no better. This
keeps ranking 1000 recipients cheap without weakening any accusation: no alpha worth
accusing at is anywhere near 1e-3.
"""


def rank(
    code: TardosCode,
    y: Sequence[int | None] | np.ndarray,
    bound_gate: float = BOUND_GATE,
    always_bound: int = 5,
) -> list[Accusation]:
    """Every recipient scored and sorted, most suspicious first.

    Tracing reports the runners-up alongside the accused: a top score that is barely
    above the second is a different kind of evidence from one that is ten sigma clear,
    and hiding that would be dishonest.
    """
    yv = as_y(y, code.params.m)
    sign = sign_vector(yv)
    raw = _scores_from_sign(code, sign)
    tail = TailBound(code, yv)
    m_eff = tail.m_eff
    n = code.params.n
    order = np.argsort(-raw)
    log10_gate = math.log10(bound_gate)

    out: list[Accusation] = []
    still_computing = m_eff > 0
    for position, j_np in enumerate(order):
        j = int(j_np)
        raw_j = float(raw[j])
        if m_eff == 0:
            z, pv, log10_pv = 0.0, 1.0, 0.0
        else:
            z = raw_j / math.sqrt(m_eff)
            pv = p_value_for_z(z, n)
            log10_pv = log10_p_value_for_z(z, n)

        want_bound = m_eff > 0 and (still_computing or position < always_bound)
        if want_bound:
            # A cheap single-lambda bound is already valid; refine only when the answer
            # is close enough to an accusation threshold for tightness to matter.
            coarse = tail.log10_bound(raw_j, refine=False)
            if coarse > log10_gate:
                still_computing = False
                log10_bound = coarse
            else:
                log10_bound = tail.log10_bound(raw_j, refine=True)
            bound = 10.0**log10_bound if log10_bound > -300 else 0.0
        else:
            bound, log10_bound = 1.0, 0.0

        out.append(
            Accusation(
                recipient_index=j,
                raw_score=raw_j,
                z_score=z,
                p_value=pv,
                log10_p_value=log10_pv,
                p_bound=bound,
                log10_p_bound=log10_bound,
                p_bound_exact=want_bound,
                m_eff=m_eff,
            )
        )
    return out


def accuse(
    code: TardosCode, y: Sequence[int | None] | np.ndarray, alpha: float = 1e-6
) -> list[Accusation]:
    """Only the recipients whose *provable* false-accusation bound clears alpha.

    Gated on ``p_bound``, not on the Gaussian ``p_value``. The Gaussian tail is not
    conservative here -- measured, not suspected -- and a system whose single claim is
    a stated false-accusation probability may not quote an optimistic one.

    An empty list is a legitimate and common answer. It means the leaked copy does not
    carry enough evidence to name anybody at the confidence asked for, not that the
    document was never fingerprinted.
    """
    return [a for a in rank(code, y) if a.p_bound < alpha]


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
