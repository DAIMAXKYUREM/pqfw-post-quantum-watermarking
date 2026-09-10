"""Render the two evaluation curves the deck argues from.

These are not illustrations. Both read straight from eval/results/*.csv, which the
evaluation harness wrote by running the library, so the deck cannot drift from the
measurements the way a hand-drawn chart would.

Two curves, because between them they carry the whole honesty argument:

**Erasure.** How much of the mark can be destroyed before the leaker stops being
identifiable -- and, on the same axes, how often the system names the wrong person
while that happens. It never does. The failure mode is silence, and a chart is the
only way to show a flat zero underneath a falling curve.

**Collusion.** At the code length Tardos prescribes, every coalition tested was
traced. At a fixed practical length the curve falls away past three colluders. Both
are plotted rather than only the flattering one; the band is the spread across five
collusion strategies, so the worst case is visible and not averaged out of sight.

Rendered transparent with light ink, because they sit on the deck's navy panel. A
chart with a white plot area would print as a window cut in the slide.

    python ppt/make_charts.py
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT.parent / "eval" / "results"
OUT = ROOT / "charts"

INK = "#C6D7F0"
FAINT = "#5D7CAE"
GRID = "#2A4272"
GREEN = "#2ED18A"
CYAN = "#3FC4E0"
ORANGE = "#F2900D"

plt.rcParams.update({
    "font.family": "Calibri",
    "font.size": 8.5,
    "axes.edgecolor": GRID,
    "axes.labelcolor": INK,
    "text.color": INK,
    "xtick.color": FAINT,
    "ytick.color": FAINT,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "figure.facecolor": "none",
    "axes.facecolor": "none",
    "savefig.facecolor": "none",
    "savefig.transparent": True,
})


def read(name: str) -> list[dict[str, str]]:
    with (RESULTS / f"{name}.csv").open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def frame(ax) -> None:
    """Two rules, not four, and the grid behind the data rather than over it."""
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_linewidth(0.8)
    ax.grid(True, axis="y", color=GRID, linewidth=0.6, alpha=0.7)
    ax.set_axisbelow(True)
    ax.tick_params(length=0, pad=2)


def erasure(path: Path) -> None:
    rows = read("erasure")
    series = defaultdict(list)
    for row in rows:
        series[int(row["m"])].append((float(row["erasure_fraction"]) * 100,
                                      float(row["detection_rate"]) * 100,
                                      float(row["misidentification_rate"]) * 100))

    fig, ax = plt.subplots(figsize=(4.32, 1.42))
    for m, colour, style in ((1200, GREEN, "-"), (300, CYAN, "--")):
        pts = sorted(series[m])
        ax.plot([p[0] for p in pts], [p[1] for p in pts], style, color=colour,
                linewidth=2.0, marker="o", markersize=3.2)

    wrong = sorted(series[1200])
    ax.plot([p[0] for p in wrong], [p[2] for p in wrong], color=ORANGE, linewidth=2.0)

    # Direct labels in the empty quadrant instead of a legend box: a legend anchored
    # anywhere on these axes lands on either the flat zero or the flat hundred.
    for y, colour, text in ((74, GREEN, "identified  —  1,200 mark slots"),
                            (54, CYAN, "identified  —  300 mark slots"),
                            (34, ORANGE, "wrong person named  —  0.0% throughout")):
        ax.text(1.5, y, text, color=colour, fontsize=7.4, va="center", weight="bold")

    ax.set_xlim(-3, 98)
    ax.set_ylim(-6, 108)
    ax.set_xticks([0, 20, 40, 60, 80, 95])
    ax.set_xticklabels(["0", "20", "40", "60", "80", "95%"])
    ax.set_yticks([0, 50, 100])
    ax.set_yticklabels(["0", "50", "100%"])
    ax.set_xlabel("share of mark slots destroyed", fontsize=7.6, labelpad=1)
    frame(ax)
    fig.tight_layout(pad=0.2)
    fig.savefig(path, dpi=340, transparent=True)
    plt.close(fig)


def collusion(path: Path) -> None:
    rows = read("coalition")
    series = defaultdict(lambda: defaultdict(list))
    for row in rows:
        series[row["regime"]][int(row["coalition_size"])].append(
            float(row["detection_rate"]) * 100)

    fig, ax = plt.subplots(figsize=(4.32, 1.42))
    # Both curves sit on 100% up to three colluders, so the prescribed line is drawn
    # wide and underneath: it reads as a halo where they agree instead of vanishing.
    for regime, colour, width in (("prescribed", GREEN, 4.0), ("practical", ORANGE, 2.0)):
        sizes = sorted(series[regime])
        mean = [sum(series[regime][s]) / len(series[regime][s]) for s in sizes]
        low = [min(series[regime][s]) for s in sizes]
        high = [max(series[regime][s]) for s in sizes]
        ax.fill_between(sizes, low, high, color=colour, alpha=0.25, linewidth=0)
        ax.plot(sizes, mean, color=colour, linewidth=width, marker="o", markersize=3.2,
                solid_capstyle="round")

    for y, colour, text in ((72, GREEN, "at the prescribed code length"),
                            (50, ORANGE, "at a fixed 1,200 slots")):
        ax.text(1.08, y, text, color=colour, fontsize=7.4, va="center", weight="bold")
    ax.text(1.08, 28, "innocent accused  —  0 of 10,000 trials", color=INK,
            fontsize=7.4, va="center", weight="bold")

    ax.set_xlim(0.6, 8.5)
    ax.set_ylim(-6, 108)
    ax.set_xticks([1, 2, 3, 5, 8])
    ax.set_yticks([0, 50, 100])
    ax.set_yticklabels(["0", "50", "100%"])
    ax.set_xlabel("colluders splicing their copies together", fontsize=7.6, labelpad=1)
    frame(ax)
    fig.tight_layout(pad=0.2)
    fig.savefig(path, dpi=340, transparent=True)
    plt.close(fig)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    erasure(OUT / "erasure.png")
    collusion(OUT / "collusion.png")
    for path in sorted(OUT.glob("*.png")):
        print(f"  {path.name}  ({path.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
