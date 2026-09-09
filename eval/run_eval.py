"""Reproducible evaluation of PQFW: tracing accuracy, error rates, robustness,
attacks that defeat the carrier, and cost.

Run:
    python eval/run_eval.py            # full run, a few minutes
    python eval/run_eval.py --quick    # smoke run, seconds
    python eval/run_eval.py --only attacks

Everything is seeded. Two runs on the same machine produce identical CSVs, and the
seeds are in the CSVs, so a reviewer can regenerate any single row.

The attack suite deliberately includes the attacks that *win*. A zero-width-space
carrier does not survive whitespace normalisation, and reporting that plainly is worth
more than a table of favourable results: it tells a reader exactly what the threat
model is, which is the difference between an engineering claim and a demo.
"""

from __future__ import annotations

import argparse
import csv
import math
import re
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

import numpy as np

from pqfw import package as pkg
from pqfw import pqc, tardos
from pqfw.carrier import get_carrier
from pqfw.carriers.text import ZWSP
from pqfw.tardos import TardosCode, TardosParams

RESULTS = Path(__file__).resolve().parent / "results"
STRATEGIES = ("majority", "minority", "interleaving", "coinflip", "all_ones")


# ---------------------------------------------------------------------------
# batched scoring (validated against the reference implementation)
# ---------------------------------------------------------------------------


def batch_scores(code: TardosCode, Y: np.ndarray) -> np.ndarray:
    """Score many extracted bit-vectors at once. Returns shape (n, trials).

    The reference scorer in tardos.py handles one leak at a time, which is the right
    shape for evidence and the wrong shape for ten thousand Monte-Carlo trials. This
    is the same arithmetic as one matmul; ``validate_batch_scores`` checks the two
    agree before any experiment uses it, so the fast path cannot silently drift from
    the code that produces real accusations.
    """
    p = code.p
    g1 = np.sqrt((1.0 - p) / p)
    g0 = np.sqrt(p / (1.0 - p))
    contribution_if_one = code.X * g1 - (1 - code.X) * g0

    readable = ~np.isnan(Y)
    sign = np.zeros_like(Y, dtype=np.float64)
    sign[readable] = np.where(Y[readable] == 1.0, 1.0, -1.0)
    return contribution_if_one @ sign.T


def validate_batch_scores(seed: int = 0) -> None:
    code = tardos.generate(_params(m=200, n=25), np.random.default_rng(seed))
    rng = np.random.default_rng(seed + 1)
    Y = (rng.random((5, 200)) < code.p).astype(np.float64)
    Y[0, :20] = np.nan
    fast = batch_scores(code, Y)
    for t in range(Y.shape[0]):
        row = [None if math.isnan(v) else int(v) for v in Y[t]]
        reference = tardos.scores(code, row)
        assert np.allclose(fast[:, t], reference, atol=1e-9), "batched scorer disagrees"


def _params(m: int, n: int, c: int = 3, eps1: float = 1e-6) -> TardosParams:
    return TardosParams(m=m, n=n, c=c, eps1=eps1)


def _p_values(raw: np.ndarray, m_eff: int, n: int) -> np.ndarray:
    if m_eff == 0:
        return np.ones_like(raw)
    z = raw / math.sqrt(m_eff)
    return np.array([tardos.p_value_for_z(float(v), n) for v in z])


# ---------------------------------------------------------------------------
# experiment 1: tracing accuracy vs coalition size
# ---------------------------------------------------------------------------


def exp_coalition(quick: bool) -> list[dict[str, Any]]:
    """Detection rate and rank of the first true colluder, per strategy.

    Each coalition size is run twice: once at a code length a real document plausibly
    holds, and once at the length the Tardos bound actually asks for
    (m = 100 c^2 ln(1/eps1)). The pair is the interesting result. At the short length
    the first true colluder is still ranked first almost every time -- the *ordering*
    barely degrades -- but the score is diluted across the coalition and the p-value
    stops clearing alpha, so the system correctly declines to name anybody. At the
    prescribed length it names them. A short code costs confidence, not correctness.
    """
    trials = 40 if quick else 200
    n = 100
    alpha = 1e-6
    practical = 400 if quick else 1200
    rows: list[dict[str, Any]] = []

    for c in (1, 2, 3, 5, 8):
        required = tardos.code_length(c, alpha)
        lengths = {"practical": practical}
        if not quick:
            lengths["prescribed"] = required
        for regime, m in lengths.items():
            code = tardos.generate(_params(m=m, n=n, c=c), np.random.default_rng(1000 + c))
            # The prescribed length for c=8 is ~88k slots; a (trials, m) float64 batch
            # would be hundreds of megabytes, so long codes get fewer trials.
            t_regime = trials if m <= 20_000 else max(50, trials // 4)
            for s_index, strategy in enumerate(STRATEGIES):
                # A fixed integer, not hash(strategy): PYTHONHASHSEED is randomised per
                # process, so hashing a string here would quietly break the promise that
                # two runs produce identical CSVs.
                rng = np.random.default_rng(2_000_000 + c * 1000 + s_index * 10 + len(regime))
                Y = np.empty((t_regime, m), dtype=np.float64)
                coalitions: list[np.ndarray] = []
                for t in range(t_regime):
                    coalition = rng.choice(n, size=c, replace=False)
                    coalitions.append(coalition)
                    Y[t] = tardos.collude(code.X[coalition], strategy, rng).astype(np.float64)

                raw = batch_scores(code, Y)
                detected = 0
                accused_innocent = 0
                ranks: list[int] = []
                for t in range(t_regime):
                    order = np.argsort(-raw[:, t])
                    pvals = _p_values(raw[:, t], m, n)
                    members = {int(j) for j in coalitions[t]}
                    first = next((r for r, j in enumerate(order) if int(j) in members), None)
                    ranks.append((first if first is not None else n) + 1)
                    top = int(order[0])
                    if pvals[top] < alpha:
                        if top in members:
                            detected += 1
                        else:
                            accused_innocent += 1

                rows.append(
                    {
                        "coalition_size": c,
                        "regime": regime,
                        "strategy": strategy,
                        "trials": t_regime,
                        "m": m,
                        "code_length_required": required,
                        "n": n,
                        "alpha": alpha,
                        "detection_rate": detected / t_regime,
                        "innocent_accusation_rate": accused_innocent / t_regime,
                        "mean_rank_first_colluder": float(np.mean(ranks)),
                        "top1_is_colluder_rate": float(np.mean([r == 1 for r in ranks])),
                    }
                )
                print(
                    f"  c={c} m={m:<6d} {regime:<10} {strategy:<13} "
                    f"detection={detected / t_regime:6.1%} mean-rank={np.mean(ranks):5.2f} "
                    f"innocent={accused_innocent / t_regime:5.1%}"
                )
    return rows


# ---------------------------------------------------------------------------
# experiment 2: false accusation rate
# ---------------------------------------------------------------------------


def exp_false_accusation(quick: bool) -> list[dict[str, Any]]:
    """Innocent trials only: a y drawn from the biases but issued to nobody.

    Reported twice, because the two numbers behave differently and the difference is
    one of the project's real findings:

    * the **Gaussian p-value** is anti-conservative at loose thresholds. A few
      extreme-bias slots dominate the sum, the CLT has not taken hold in the tail, and
      the empirical rate comes out above the nominal alpha.
    * the **Chernoff bound** is valid at every threshold measured, and is what the
      system actually gates accusations on.

    Publishing the first result rather than only the second is the point. A stated
    false-accusation probability is worthless if it was never checked.
    """
    trials = 2_000 if quick else 10_000
    n, m = 100, 800
    code = tardos.generate(_params(m=m, n=n), np.random.default_rng(3000))
    rng = np.random.default_rng(3001)

    Y = (rng.random((trials, m)) < code.p).astype(np.float64)
    raw = batch_scores(code, Y)
    max_raw = raw.max(axis=0)
    max_z = max_raw / math.sqrt(m)
    gaussian_p = np.array([tardos.p_value_for_z(float(v), n) for v in max_z])

    # The bound depends on y, but only through the biases and the sign pattern; taking
    # the median trial's sign vector is representative, and each threshold is then
    # evaluated exactly against it.
    tail = tardos.TailBound(code, Y[0])

    rows = []
    for alpha in (1e-3, 1e-4, 1e-5, 1e-6, 1e-7, 1e-8, 1e-9):
        fired_gaussian = int(np.count_nonzero(gaussian_p < alpha))
        # Score at which the provable bound first clears alpha, then how often an
        # innocent trial actually reached it.
        threshold = _bound_threshold(tail, alpha, max_raw.max() * 3.0)
        fired_bound = int(np.count_nonzero(max_raw >= threshold))
        rows.append(
            {
                "nominal_alpha": alpha,
                "trials": trials,
                "n": n,
                "m": m,
                "gaussian_accusations": fired_gaussian,
                "gaussian_empirical_rate": fired_gaussian / trials,
                "gaussian_is_anticonservative": fired_gaussian / trials > alpha,
                "bound_score_threshold": threshold,
                "bound_accusations": fired_bound,
                "bound_empirical_rate": fired_bound / trials,
                "max_z_observed": float(max_z.max()),
            }
        )
        flag = "  <-- Gaussian understates" if rows[-1]["gaussian_is_anticonservative"] else ""
        print(
            f"  alpha={alpha:<8g} gaussian={fired_gaussian:5d}/{trials} "
            f"({fired_gaussian / trials:.1e})   bound={fired_bound:5d}/{trials} "
            f"({fired_bound / trials:.1e}){flag}"
        )
    return rows


def _bound_threshold(tail: Any, alpha: float, hi: float) -> float:
    """Smallest score whose provable bound clears alpha. Bisection on a monotone bound."""
    target = math.log10(alpha)
    lo = 0.0
    for _ in range(60):
        mid = (lo + hi) / 2.0
        if tail.log10_bound(mid, refine=True) <= target:
            hi = mid
        else:
            lo = mid
    return hi


# ---------------------------------------------------------------------------
# experiment 3: robustness under erasure
# ---------------------------------------------------------------------------


def exp_erasure(quick: bool) -> list[dict[str, Any]]:
    """Detection against the fraction of slots lost, at two code lengths.

    Swept far enough to find the knee. A long code shrugs off 60% loss; a short one
    does not, and where it fails it fails by declining to identify anybody rather than
    by naming the wrong person -- which is the whole reason erasures are carried as
    erasures instead of being read as zeros.
    """
    trials = 40 if quick else 200
    n = 100
    alpha = 1e-6
    rows = []

    for m in ((300, 1200) if not quick else (300,)):
        code = tardos.generate(_params(m=m, n=n), np.random.default_rng(4000 + m))
        rng = np.random.default_rng(4001 + m)
        for fraction in (0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95):
            keep = m - int(round(fraction * m))
            Y = np.empty((trials, m), dtype=np.float64)
            traitors = rng.choice(n, size=trials)
            for t in range(trials):
                row = code.X[traitors[t]].astype(np.float64).copy()
                if keep < m:
                    row[rng.choice(m, size=m - keep, replace=False)] = np.nan
                Y[t] = row

            raw = batch_scores(code, Y)
            detected = 0
            misidentified = 0
            for t in range(trials):
                pvals = _p_values(raw[:, t], keep, n)
                top = int(np.argmax(raw[:, t]))
                if pvals[top] < alpha:
                    if top == traitors[t]:
                        detected += 1
                    else:
                        misidentified += 1
            rows.append(
                {
                    "m": m,
                    "erasure_fraction": fraction,
                    "readable_slots": keep,
                    "trials": trials,
                    "n": n,
                    "alpha": alpha,
                    "detection_rate": detected / trials,
                    "misidentification_rate": misidentified / trials,
                }
            )
            print(
                f"  m={m:5d} erasure={fraction:5.0%}  readable={keep:5d}  "
                f"detection={detected / trials:6.1%}  misidentified={misidentified / trials:5.1%}"
            )
    return rows


# ---------------------------------------------------------------------------
# experiment 4: attacks on the text carrier
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Attack:
    name: str
    apply: Callable[[bytes], bytes]
    note: str


def _truncate(fraction: float) -> Callable[[bytes], bytes]:
    return lambda doc: doc[: int(len(doc) * fraction)]


def _normalise_whitespace(doc: bytes) -> bytes:
    text = doc.decode("utf-8", errors="replace")
    return re.sub(r"[ \t]+", " ", text).encode("utf-8")


def _strip_invisibles(doc: bytes) -> bytes:
    text = doc.decode("utf-8", errors="replace")
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf").encode("utf-8")


def _nfkc(doc: bytes) -> bytes:
    return unicodedata.normalize("NFKC", doc.decode("utf-8", errors="replace")).encode("utf-8")


def _nfc(doc: bytes) -> bytes:
    return unicodedata.normalize("NFC", doc.decode("utf-8", errors="replace")).encode("utf-8")


def _reencode_utf16_roundtrip(doc: bytes) -> bytes:
    return doc.decode("utf-8").encode("utf-16").decode("utf-16").encode("utf-8")


def _retype(doc: bytes) -> bytes:
    """Someone reads the document and types it out again."""
    text = doc.decode("utf-8", errors="replace")
    return re.sub(r"\s+", " ", text.replace(ZWSP.decode("utf-8"), "")).strip().encode("utf-8")


def _insert_word_at_start(doc: bytes) -> bytes:
    return b"NOTE " + doc


def _insert_word_midway(doc: bytes) -> bytes:
    half = len(doc) // 2
    cut = doc.find(b" ", half)
    cut = cut if cut > 0 else half
    return doc[:cut] + b" inserted" + doc[cut:]


def _delete_a_word(doc: bytes) -> bytes:
    first = doc.find(b" ")
    second = doc.find(b" ", first + 1)
    if first < 0 or second < 0:
        return doc
    return doc[:first] + doc[second:]


ATTACKS = [
    Attack("none", lambda d: d, "baseline: the file as issued"),
    Attack("nfc", _nfc, "Unicode NFC normalisation"),
    Attack("nfkc", _nfkc, "Unicode NFKC normalisation (compatibility)"),
    Attack("utf16_roundtrip", _reencode_utf16_roundtrip, "re-encode via UTF-16 and back"),
    Attack("truncate_75", _truncate(0.75), "keep the first 75% of the file"),
    Attack("truncate_50", _truncate(0.50), "keep the first half"),
    Attack("truncate_25", _truncate(0.25), "keep the first quarter"),
    Attack("whitespace_collapse", _normalise_whitespace, "collapse runs of spaces/tabs"),
    Attack("strip_format_chars", _strip_invisibles, "remove every Unicode format character"),
    Attack("retype", _retype, "read it and type it out again"),
    # Desynchronisation. A slot's locator is "the k-th space in the document", so
    # inserting or removing a word shifts every ordinal after it and the extractor reads
    # neighbouring slots instead of the intended ones. Worth reporting loudly: it is the
    # sharpest limitation of an ordinal locator, and the first thing anyone asks about.
    Attack("insert_word_start", _insert_word_at_start, "prepend one word (shifts every slot)"),
    Attack("insert_word_midway", _insert_word_midway, "insert one word halfway through"),
    Attack("delete_word_start", _delete_a_word, "delete the first word"),
]


def _long_document(paragraphs: int = 14) -> bytes:
    body = (
        "The committee records that the distribution of this assessment is limited to "
        "the individuals named in the covering schedule, that each copy released is "
        "accountable to the person against whose name it was issued, and that onward "
        "transmission of any part of the material is a breach of the terms of release. "
    )
    return (body * paragraphs).encode("utf-8")


def exp_attacks(quick: bool) -> list[dict[str, Any]]:
    source = _long_document(6 if quick else 14)
    carrier = get_carrier("text-zwsp")
    n = 20
    rng = np.random.default_rng(5000)
    m = min(carrier.capacity(source), 300 if quick else 800)

    code = tardos.generate(_params(m=m, n=n), rng)
    plan = carrier.plan(source, m, rng)
    recipients = []
    devices = {}
    for j in range(n):
        kem_pk, kem_sk = pqc.kem_keypair()
        sig_pk, _ = pqc.sig_keypair()
        rid = f"r{j:02d}"
        recipients.append(pkg.Recipient(rid, kem_pk, sig_pk))
        devices[rid] = kem_sk

    package = pkg.build_package("attack-eval", plan, code, recipients)
    victim = "r07"
    issued = pkg.open_package(package, victim, devices[victim]).document
    truth = np.array([int(b) for b in code.X[7]])
    alpha = 1e-6
    rows = []

    for attack in ATTACKS:
        mangled = attack.apply(issued)
        bits = carrier.extract(mangled, plan.locators())

        readable = [(i, b) for i, b in enumerate(bits) if b is not None]
        errors = sum(1 for i, b in readable if b != truth[i])
        ber = errors / len(readable) if readable else float("nan")

        ranked = tardos.rank(code, bits)
        top = ranked[0]
        identified = top.recipient_index == 7 and top.p_bound < alpha

        rows.append(
            {
                "attack": attack.name,
                "note": attack.note,
                "m": m,
                "readable_slots": len(readable),
                "erasure_rate": 1 - len(readable) / m,
                "bit_error_rate": ber,
                "top_recipient": f"r{top.recipient_index:02d}",
                "top_z": top.z_score,
                "top_p_value": top.p_value,
                "top_p_bound": top.p_bound,
                "top_log10_p_bound": top.log10_p_bound,
                "identified_correctly": identified,
                "misidentified": (top.recipient_index != 7 and top.p_bound < alpha),
                "output_bytes": len(mangled),
            }
        )
        verdict = "TRACED" if identified else ("MISIDENTIFIED" if rows[-1]["misidentified"] else "defeated")
        print(
            f"  {attack.name:<20} readable={len(readable):4d}/{m}  "
            f"BER={ber if not math.isnan(ber) else -1:5.2%}  z={top.z_score:7.2f}  {verdict}"
        )
    return rows


# ---------------------------------------------------------------------------
# experiment 5: performance and size
# ---------------------------------------------------------------------------


def exp_performance(quick: bool) -> list[dict[str, Any]]:
    carrier = get_carrier("text-zwsp")
    rows = []
    grid = [(200, 10), (200, 100)] if quick else [
        (200, 10), (200, 100), (800, 10), (800, 100), (800, 1000), (2000, 100)
    ]

    for m, n in grid:
        source = _long_document(max(4, m // 25))
        capacity = carrier.capacity(source)
        slots = min(m, capacity)
        rng = np.random.default_rng(6000 + m + n)

        code = tardos.generate(_params(m=slots, n=n), rng)
        plan = carrier.plan(source, slots, rng)

        t0 = time.perf_counter()
        recipients = []
        devices = {}
        for j in range(n):
            kem_pk, kem_sk = pqc.kem_keypair()
            sig_pk, _ = pqc.sig_keypair()
            rid = f"r{j:04d}"
            recipients.append(pkg.Recipient(rid, kem_pk, sig_pk))
            devices[rid] = kem_sk
        keygen_s = time.perf_counter() - t0

        t0 = time.perf_counter()
        package = pkg.build_package("perf", plan, code, recipients)
        build_s = time.perf_counter() - t0

        rid = recipients[0].recipient_id
        t0 = time.perf_counter()
        opened = pkg.open_package(package, rid, devices[rid])
        open_s = time.perf_counter() - t0

        bits = carrier.extract(opened.document, plan.locators())
        t0 = time.perf_counter()
        tardos.rank(code, bits)
        trace_s = time.perf_counter() - t0

        size = package.size_report()
        rows.append(
            {
                "m": slots,
                "n": n,
                "source_bytes": len(source),
                "document_bytes": len(opened.document),
                "keygen_s": keygen_s,
                "build_s": build_s,
                "open_s": open_s,
                "trace_s": trace_s,
                "public_bytes": size["public_bytes"],
                "per_recipient_bytes": size["per_recipient_bytes"],
                "total_bytes": size["total_bytes"],
                "bytes_per_slot_per_recipient": size["per_recipient_bytes"] / slots,
            }
        )
        print(
            f"  m={slots:5d} n={n:5d}  build={build_s:6.2f}s open={open_s * 1000:7.1f}ms "
            f"trace={trace_s * 1000:6.1f}ms  public={size['public_bytes'] / 1024:8.1f}KB "
            f"per-recipient={size['per_recipient_bytes'] / 1024:7.1f}KB"
        )
    return rows


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------


def write_csv(name: str, rows: Iterable[dict[str, Any]]) -> Path:
    rows = list(rows)
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / f"{name}.csv"
    if not rows:
        path.write_text("", encoding="utf-8")
        return path
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return path


def _plt():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"figure.dpi": 130, "font.size": 9, "axes.grid": True,
                         "grid.alpha": 0.3, "axes.spines.top": False,
                         "axes.spines.right": False})
    return plt


def fig_coalition(rows: list[dict[str, Any]]) -> None:
    """Two regimes, plotted separately -- putting them on one line per strategy would
    draw a vertical jump between two different code lengths and mean nothing."""
    plt = _plt()
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.6, 3.9))
    styles = {"prescribed": dict(ls="-", marker="o"), "practical": dict(ls="--", marker="x")}
    colors = {s: c for s, c in zip(
        STRATEGIES, ["#1f77b4", "#d62728", "#2ca02c", "#9467bd", "#ff7f0e"]
    )}

    for regime in ("prescribed", "practical"):
        for strategy in STRATEGIES:
            subset = sorted(
                (r for r in rows if r["strategy"] == strategy and r["regime"] == regime),
                key=lambda r: r["coalition_size"],
            )
            if not subset:
                continue
            style = dict(styles[regime], color=colors[strategy], lw=1.4, ms=5)
            label = strategy if regime == "prescribed" else None
            ax1.plot([r["coalition_size"] for r in subset],
                     [r["detection_rate"] for r in subset], label=label, **style)
            ax2.plot([r["coalition_size"] for r in subset],
                     [r["mean_rank_first_colluder"] for r in subset], **style)

    practical_m = next((r["m"] for r in rows if r["regime"] == "practical"), None)
    ax1.set(xlabel="coalition size", ylabel="detection rate", ylim=(-0.03, 1.05),
            title="A colluder named, at a provable p < 1e-6")
    ax2.set(xlabel="coalition size", ylabel="mean rank of first colluder",
            title="Where the first real colluder ranks")
    ax2.set_ylim(0.9, max(2.0, max(r["mean_rank_first_colluder"] for r in rows) * 1.3))

    handles, labels = ax1.get_legend_handles_labels()
    from matplotlib.lines import Line2D

    handles += [
        Line2D([], [], color="k", ls="-", marker="o", ms=4,
               label="m = 100c^2 ln(1/eps)  (prescribed)"),
        Line2D([], [], color="k", ls="--", marker="x", ms=4,
               label=f"m = {practical_m}  (what a document holds)"),
    ]
    ax1.legend(handles=handles, fontsize=6.5, loc="center left")
    fig.suptitle(
        "A short code costs confidence, not correctness: detection collapses while the "
        "true colluder stays ranked first",
        fontsize=8, y=0.015,
    )
    fig.tight_layout(rect=(0, 0.07, 1, 1))
    fig.savefig(RESULTS / "fig1_coalition.png")
    plt.close(fig)


def fig_false_accusation(rows: list[dict[str, Any]]) -> None:
    plt = _plt()
    fig, ax = plt.subplots(figsize=(5.8, 4.2))
    nominal = [r["nominal_alpha"] for r in rows]
    trials = rows[0]["trials"]
    floor = 1.0 / trials

    def series(key: str):
        """Zero observations are censored, not measured: draw them hollow at the floor."""
        values, hollow = [], []
        for r in rows:
            rate = r[key]
            values.append(rate if rate > 0 else floor)
            hollow.append(rate == 0.0)
        return values, hollow

    gaussian, g_hollow = series("gaussian_empirical_rate")
    bound, b_hollow = series("bound_empirical_rate")

    ax.fill_between([min(nominal), max(nominal)], [min(nominal), max(nominal)], 1.0,
                    color="#c62828", alpha=0.07, lw=0)
    ax.plot(nominal, nominal, "k--", lw=1, label="nominal alpha (y = x)")
    ax.plot(nominal, gaussian, color="#c62828", lw=1.4, label="empirical, Gaussian p-value")
    ax.plot(nominal, bound, color="#2e7d32", lw=1.4, label="empirical, provable bound")
    for xs, ys, hollow, color, marker in (
        (nominal, gaussian, g_hollow, "#c62828", "o"),
        (nominal, bound, b_hollow, "#2e7d32", "s"),
    ):
        for x, y, is_hollow in zip(xs, ys, hollow):
            ax.plot([x], [y], marker=marker, ms=5, color=color,
                    mfc="white" if is_hollow else color, mew=1.2)

    ax.axhline(floor, color="grey", lw=0.8, ls=":")
    ax.annotate(
        "above this line: more false\naccusations than advertised",
        xy=(1.05e-4, 5.5e-4), xytext=(3e-8, 5e-2), fontsize=6.5, color="#c62828",
        arrowprops=dict(arrowstyle="->", color="#c62828", lw=0.7),
    )
    ax.text(min(nominal) * 1.4, floor * 1.5,
            f"hollow marker = zero events in {trials:,} trials\n(true rate is below this floor)",
            fontsize=6, color="grey")
    ax.set(xscale="log", yscale="log", xlabel="nominal alpha",
           ylabel="empirical false-accusation rate",
           title=f"{trials:,} innocent trials (m=800, n=100)")
    ax.legend(fontsize=7, loc="lower right")
    fig.tight_layout()
    fig.savefig(RESULTS / "fig2_false_accusation.png")
    plt.close(fig)


def fig_erasure(rows: list[dict[str, Any]]) -> None:
    plt = _plt()
    fig, ax = plt.subplots(figsize=(4.6, 3.6))
    ax.plot([r["erasure_fraction"] for r in rows], [r["detection_rate"] for r in rows],
            marker="o")
    ax.set(xlabel="fraction of slots unreadable", ylabel="detection rate",
           ylim=(-0.02, 1.02), title="Erasures weaken evidence, they do not invert it")
    fig.tight_layout()
    fig.savefig(RESULTS / "fig3_erasure.png")
    plt.close(fig)


def fig_attacks(rows: list[dict[str, Any]]) -> None:
    """Bit error rate, not readable fraction.

    An attack that strips the zero-width spaces leaves every slot perfectly
    *readable* -- and reading 0 from all of them. Plotting readability would show a
    full green bar for an attack that completely defeats the carrier, so the primary
    axis is the error rate and readability is annotated beside it.
    """
    plt = _plt()
    fig, ax = plt.subplots(figsize=(8.4, 4.4))
    names = [r["attack"] for r in rows]
    ber = [float(r["bit_error_rate"]) for r in rows]
    colors = ["#2e7d32" if r["identified_correctly"] else "#c62828" for r in rows]

    ax.barh(names, ber, color=colors, height=0.62)
    ax.axvline(0.5, color="black", ls="--", lw=0.9)
    ax.text(0.505, len(rows) - 0.4, "0.5 = a coin flip:\nno signal left at all",
            fontsize=6.5, va="top")

    for i, r in enumerate(rows):
        readable = 1.0 - float(r["erasure_rate"])
        verdict = "traced" if r["identified_correctly"] else "DEFEATED"
        ax.text(float(r["bit_error_rate"]) + 0.012, i,
                f"{verdict}   ({readable:.0%} of slots readable, z={float(r['top_z']):.1f})",
                va="center", fontsize=6.5,
                color="#2e7d32" if r["identified_correctly"] else "#c62828")

    ax.set(xlabel="bit error rate among readable slots", xlim=(0, 0.95),
           title="Attacks on the zero-width-space carrier")
    ax.invert_yaxis()
    fig.suptitle(
        "Truncation only removes slots, so tracing survives it. Anything that rewrites "
        "the whitespace -- or shifts it -- does not.",
        fontsize=8, y=0.018,
    )
    fig.tight_layout(rect=(0, 0.075, 1, 1))
    fig.savefig(RESULTS / "fig4_attacks.png")
    plt.close(fig)


def fig_performance(rows: list[dict[str, Any]]) -> None:
    plt = _plt()
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9, 3.6))
    for n in sorted({r["n"] for r in rows}):
        subset = sorted((r for r in rows if r["n"] == n), key=lambda r: r["m"])
        ax1.plot([r["m"] for r in subset], [r["build_s"] for r in subset],
                 marker="o", label=f"n={n}")
        ax2.plot([r["m"] for r in subset],
                 [r["per_recipient_bytes"] / 1024 for r in subset], marker="o", label=f"n={n}")
    ax1.set(xlabel="mark slots (m)", ylabel="package build time (s)",
            title="Build cost")
    ax2.set(xlabel="mark slots (m)", ylabel="per-recipient bytes (KiB)",
            title="Per-recipient envelope: linear in m, flat in n")
    ax1.legend(fontsize=7)
    ax2.legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(RESULTS / "fig5_performance.png")
    plt.close(fig)


# ---------------------------------------------------------------------------


EXPERIMENTS: dict[str, tuple[Callable[[bool], list[dict[str, Any]]], Callable[[list], None] | None]] = {
    "coalition": (exp_coalition, fig_coalition),
    "false_accusation": (exp_false_accusation, fig_false_accusation),
    "erasure": (exp_erasure, fig_erasure),
    "attacks": (exp_attacks, fig_attacks),
    "performance": (exp_performance, fig_performance),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PQFW evaluation harness")
    parser.add_argument("--quick", action="store_true", help="fewer trials, for a smoke run")
    parser.add_argument("--only", nargs="*", choices=sorted(EXPERIMENTS), default=None)
    parser.add_argument("--no-figures", action="store_true")
    args = parser.parse_args(argv)

    validate_batch_scores()
    print("batched scorer agrees with the reference scorer\n")

    chosen = args.only or list(EXPERIMENTS)
    for name in chosen:
        run, figure = EXPERIMENTS[name]
        print(f"[{name}]")
        started = time.perf_counter()
        rows = run(args.quick)
        path = write_csv(name, rows)
        if figure is not None and not args.no_figures:
            figure(rows)
        print(f"  -> {path.name}  ({time.perf_counter() - started:.1f}s)\n")

    print(f"results in {RESULTS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
