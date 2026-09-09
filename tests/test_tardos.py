"""Task 2: symmetric Tardos codes.

If the g0/g1 signs are swapped, everything downstream still *runs* -- packages build,
recipients decrypt, the ledger verifies -- and tracing quietly accuses innocents. So
these tests check the statistics, not just the plumbing:

* an innocent recipient's score must be centred on zero with unit variance per slot,
* a traitor's score must grow like m,
* and the false-accusation rate must actually track the alpha we advertise.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from pqfw import tardos
from pqfw.tardos import TardosParams


def _params(m: int, n: int, c: int = 3, eps1: float = 1e-6) -> TardosParams:
    return TardosParams(m=m, n=n, c=c, eps1=eps1)


# ---------------------------------------------------------------------------
# code construction
# ---------------------------------------------------------------------------


def test_code_length_grows_with_coalition_and_precision() -> None:
    assert tardos.code_length(3, 1e-6) > tardos.code_length(2, 1e-6)
    assert tardos.code_length(3, 1e-9) > tardos.code_length(3, 1e-6)
    # m = constant * c^2 * ln(1/eps1)
    assert tardos.code_length(2, 1e-6, constant=100.0) == math.ceil(
        100.0 * 4 * math.log(1e6)
    )


def test_bias_range() -> None:
    """Biases live strictly inside the arcsine truncation and average to one half."""
    c = 3
    code = tardos.generate(_params(m=10_000, n=2, c=c), np.random.default_rng(1))
    t = 1.0 / (300 * c)
    assert code.p.shape == (10_000,)
    assert np.all(code.p >= t - 1e-12)
    assert np.all(code.p <= 1.0 - t + 1e-12)
    assert abs(float(code.p.mean()) - 0.5) < 0.02


def test_codewords_follow_their_bias() -> None:
    """X[:, i] ~ Bernoulli(p_i), drawn independently per recipient."""
    code = tardos.generate(_params(m=200, n=4000, c=3), np.random.default_rng(2))
    assert code.X.shape == (4000, 200)
    assert code.X.dtype == np.uint8
    empirical = code.X.mean(axis=0)
    assert np.max(np.abs(empirical - code.p)) < 0.05


def test_generate_is_reproducible_from_a_seed() -> None:
    a = tardos.generate(_params(m=64, n=10), np.random.default_rng(7))
    b = tardos.generate(_params(m=64, n=10), np.random.default_rng(7))
    assert np.array_equal(a.p, b.p)
    assert np.array_equal(a.X, b.X)


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


def test_innocent_score_is_standard_normal_per_slot() -> None:
    """The distribution the p-value is computed against, checked rather than assumed."""
    code = tardos.generate(_params(m=400, n=3000), np.random.default_rng(3))
    rng = np.random.default_rng(4)
    y = (rng.random(400) < code.p).astype(np.uint8)  # a copy nobody was issued
    z = tardos.scores(code, y) / math.sqrt(400)
    assert abs(float(z.mean())) < 0.1
    assert abs(float(z.std()) - 1.0) < 0.1


def test_single_traitor_traced() -> None:
    n, c, eps1 = 50, 3, 1e-6
    m = tardos.code_length(c, eps1)
    code = tardos.generate(_params(m=m, n=n, c=c, eps1=eps1), np.random.default_rng(11))
    y = code.X[7].copy()

    accusations = tardos.accuse(code, y, alpha=1e-6)

    assert accusations, "an exact copy of recipient 7's codeword must be traceable"
    assert accusations[0].recipient_index == 7
    assert accusations[0].p_value < 1e-6
    assert accusations[0].m_eff == m


def test_innocent_false_positive_rate() -> None:
    """A random y unrelated to any codeword must almost never accuse anyone.

    With alpha=1e-6 the plan's loose bound (trials * alpha * 10) is 0.02, i.e. this
    asserts zero accusations over 2000 trials. That is the point: an inverted g0/g1
    sign convention fires on nearly every trial, so the bound does not need to be
    tight to catch it.
    """
    trials, alpha = 2000, 1e-6
    code = tardos.generate(_params(m=500, n=50), np.random.default_rng(21))
    rng = np.random.default_rng(22)
    fired = 0
    for _ in range(trials):
        y = (rng.random(500) < code.p).astype(np.uint8)
        fired += len(tardos.accuse(code, y, alpha=alpha))
    assert fired < trials * alpha * 10


@pytest.mark.parametrize("strategy", ["majority", "interleaving"])
def test_collusion_is_traced(strategy: str) -> None:
    """A coalition of three, 200 trials: at least one real colluder in the top three."""
    trials, coalition_size, top_k = 200, 3, 3
    m = tardos.code_length(3, 1e-6, constant=20.0)
    code = tardos.generate(_params(m=m, n=50, c=3), np.random.default_rng(31))
    rng = np.random.default_rng(32)

    hits = 0
    for _ in range(trials):
        coalition = rng.choice(50, size=coalition_size, replace=False)
        y = tardos.collude(code.X[coalition], strategy, rng)
        ranked = tardos.rank(code, y)
        top = {a.recipient_index for a in ranked[:top_k]}
        hits += bool(top & set(int(j) for j in coalition))
    assert hits / trials >= 0.95


def test_erasures_handled() -> None:
    """A leak with 20% of its slots unreadable is still traceable, at a weaker z."""
    m = tardos.code_length(3, 1e-6, constant=20.0)
    code = tardos.generate(_params(m=m, n=50, c=3), np.random.default_rng(41))
    rng = np.random.default_rng(42)

    y: list[int | None] = [int(b) for b in code.X[13]]
    for i in rng.choice(m, size=int(0.2 * m), replace=False):
        y[int(i)] = None

    accusations = tardos.accuse(code, y, alpha=1e-6)
    assert accusations[0].recipient_index == 13
    assert accusations[0].m_eff == m - int(0.2 * m)
    assert accusations[0].p_value < 1e-6


def test_all_erasures_accuses_nobody() -> None:
    """A document with no readable slots must not identify anyone, and must not
    divide by zero trying."""
    code = tardos.generate(_params(m=32, n=5), np.random.default_rng(51))
    y = [None] * 32
    assert tardos.accuse(code, y, alpha=1e-6) == []
    ranked = tardos.rank(code, y)
    assert all(a.m_eff == 0 and a.p_value == 1.0 for a in ranked)


def test_p_value_is_bonferroni_corrected_over_all_recipients() -> None:
    """Two codes differing only in n must report different p-values for the same z --
    searching 1000 suspects for a high score is not the same evidence as checking one.
    """
    small = tardos.generate(_params(m=200, n=10), np.random.default_rng(61))
    big = tardos.generate(_params(m=200, n=1000), np.random.default_rng(61))
    z = 5.0
    assert tardos.p_value_for_z(z, small.params.n) < tardos.p_value_for_z(z, big.params.n)


def test_log10_p_value_survives_underflow() -> None:
    """A strong trace produces a tail probability below the smallest float. Reporting
    'p = 0.0' would look like a bug, so we also carry log10(p)."""
    assert tardos.p_value_for_z(60.0, 100) == 0.0
    assert tardos.log10_p_value_for_z(60.0, 100) < -700
    assert math.isclose(
        tardos.log10_p_value_for_z(5.0, 100),
        math.log10(tardos.p_value_for_z(5.0, 100)),
        rel_tol=1e-6,
    )


def test_scores_rejects_wrong_length_y() -> None:
    code = tardos.generate(_params(m=16, n=3), np.random.default_rng(71))
    with pytest.raises(ValueError):
        tardos.scores(code, [1] * 15)
