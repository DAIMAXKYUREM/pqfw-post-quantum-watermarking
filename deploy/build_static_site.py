"""Build a static results site from real runs of the real system.

Hugging Face closed the free tier for Docker Spaces -- static Spaces are still free for
everyone, but anything that runs a server needs PRO. PQFW needs a server: the demo's
whole claim is that liboqs does the work, and reimplementing ML-KEM and the Tardos
scorer in JavaScript to fit a static host would replace the thing being demonstrated
with a copy of it that has no tests.

So this builds the honest static artefact instead: the evaluation figures, the measured
attack table, and a **captured transcript of a real end-to-end run** -- every number
produced by executing the library here, at build time, and labelled as recorded rather
than live. The interactive app is a container, and deploy/render.yaml deploys it.

    python deploy/build_static_site.py
"""

from __future__ import annotations

import csv
import html
import io
import shutil
import subprocess
import sys
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "deploy" / ".static"
RESULTS = ROOT / "eval" / "results"

sys.path.insert(0, str(ROOT / "src"))


# ---------------------------------------------------------------------------
# capture a real run
# ---------------------------------------------------------------------------


def capture_transcript() -> dict[str, str]:
    """Run the five operations for real and keep what they printed."""
    import os
    import tempfile

    from pqfw.cli import main

    workdir = Path(tempfile.mkdtemp(prefix="pqfw-site-"))
    (workdir / "report.txt").write_bytes((ROOT / "demo" / "report.txt").read_bytes())

    # Run from inside the work directory with relative paths. Absolute ones would put
    # the build machine's home directory and username into a page that gets published.
    steps = [
        ("enroll", ["enroll", "--recipients", "20", "--out", "./state"]),
        ("protect", ["protect", "--doc", "report.txt", "--state", "./state", "--seed", "42"]),
        ("open", ["open", "--doc-id", "report", "--recipient", "r07",
                  "--state", "./state", "--out", "leaked.txt"]),
        ("checkpoint", ["audit", "--state", "./state", "--checkpoint", "--no-qr"]),
        ("trace", ["trace", "--doc-id", "report", "--leaked", "leaked.txt",
                   "--state", "./state"]),
        ("tamper", ["audit", "--state", "./state", "--tamper", "0", "--no-qr"]),
        ("trace_after_tamper", ["trace", "--doc-id", "report", "--leaked", "leaked.txt",
                                "--state", "./state"]),
    ]

    captured: dict[str, str] = {}
    previous = Path.cwd()
    try:
        os.chdir(workdir)
        for name, argv in steps:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                main(argv)
            captured[name] = buffer.getvalue().rstrip()
    finally:
        os.chdir(previous)
        shutil.rmtree(workdir, ignore_errors=True)

    leaked_paths = [k for k, v in captured.items() if str(workdir) in v or "AppData" in v]
    if leaked_paths:
        raise SystemExit(f"transcript for {leaked_paths} contains a local path")
    return captured


def capture_key_binding() -> str:
    """The central security claim, executed."""
    from cryptography.exceptions import InvalidTag

    from pqfw import package as pkg
    from pqfw import pqc, tardos
    from pqfw.carrier import get_carrier
    from pqfw.carriers import text as _t  # noqa: F401
    from pqfw.tardos import TardosParams

    rng = np.random.default_rng(11)
    source = (ROOT / "demo" / "report.txt").read_bytes()
    carrier = get_carrier("text-zwsp")
    m = carrier.capacity(source)
    code = tardos.generate(TardosParams(m=m, n=8, c=3, eps1=1e-6), rng)
    plan = carrier.plan(source, m, rng)

    recipients, devices = [], {}
    for j in range(8):
        kem_pk, kem_sk = pqc.kem_keypair()
        sig_pk, _ = pqc.sig_keypair()
        rid = f"r{j:02d}"
        recipients.append(pkg.Recipient(rid, kem_pk, sig_pk))
        devices[rid] = kem_sk

    package = pkg.build_package("site", plan, code, recipients)
    bundle = pkg.unwrap_bundle(package, "r03", devices["r03"])

    lines: list[str] = []
    checked = 0
    for i in range(min(m, 400)):
        held = int(code.X[3][i])
        other = 1 - held
        pqc.aead_decrypt(bundle.vks[i], package.variant_blobs[i][held],
                         aad=pkg.variant_aad("site", i, held))
        try:
            pqc.aead_decrypt(bundle.vks[i], package.variant_blobs[i][other],
                             aad=pkg.variant_aad("site", i, other))
            lines.append(f"slot {i}: FAILED -- the other variant decrypted")
        except InvalidTag:
            checked += 1

    lines.append(f"r03 holds one variant key for each of {m} slots.")
    lines.append(f"Tried the other rendering at {checked} slots: refused at every one.")
    lines.append("")
    lines.append(f"  variant they hold      decrypts    ({checked}/{checked})")
    lines.append(f"  the other rendering    InvalidTag  ({checked}/{checked})")
    lines.append("")
    lines.append("The shared ciphertext is byte-identical for all 8 recipients:")
    lines.append(f"  public part      {len(package.public_view()):,} bytes")
    lines.append(
        f"  per recipient    {package.size_report()['per_recipient_bytes']:,} bytes"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# page
# ---------------------------------------------------------------------------


def read_csv(name: str) -> list[dict[str, str]]:
    path = RESULTS / f"{name}.csv"
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def attack_rows() -> str:
    rows = read_csv("attacks")
    out = []
    for r in rows:
        ber = float(r["bit_error_rate"])
        traced = r["identified_correctly"] == "True"
        cls = "good" if traced else "bad"
        verdict = "traced" if traced else "DEFEATS THE CARRIER"
        out.append(
            f"<tr><td><code>{html.escape(r['attack'])}</code></td>"
            f"<td>{html.escape(r['note'])}</td>"
            f"<td class='num'>{ber:.1%}</td>"
            f"<td class='num'>{float(r['top_z']):.1f}</td>"
            f"<td class='{cls}'>{verdict}</td></tr>"
        )
    return "\n".join(out)


def coalition_rows() -> str:
    rows = read_csv("coalition")
    by: dict[int, dict[str, list[float]]] = {}
    for r in rows:
        c = int(r["coalition_size"])
        by.setdefault(c, {"practical": [], "prescribed": []})
        by[c][r["regime"]].append(float(r["detection_rate"]))
    out = []
    for c in sorted(by):
        pr = by[c]["practical"]
        ps = by[c]["prescribed"]
        rank = [float(r["mean_rank_first_colluder"]) for r in rows if int(r["coalition_size"]) == c]
        span = (
            f"{min(pr):.0%}" if pr and max(pr) - min(pr) < 0.02
            else (f"{min(pr):.0%}–{max(pr):.0%}" if pr else "—")
        )
        out.append(
            f"<tr><td class='num'>{c}</td><td class='num'>{span}</td>"
            f"<td class='num good'>{min(ps):.0%}</td>"
            f"<td class='num'>{min(rank):.2f}–{max(rank):.2f}</td></tr>"
        )
    return "\n".join(out)


def fp_rows() -> str:
    out = []
    for r in read_csv("false_accusation"):
        alpha = float(r["nominal_alpha"])
        g = float(r["gaussian_empirical_rate"])
        b = float(r["bound_empirical_rate"])
        anti = r["gaussian_is_anticonservative"] == "True"
        trials = int(r["trials"])
        fmt = lambda v: f"{v:.1e}" if v > 0 else f"0 / {trials:,}"  # noqa: E731
        out.append(
            f"<tr><td class='num'>{alpha:.0e}</td>"
            f"<td class='num {'bad' if anti else ''}'>{fmt(g)}"
            f"{' &uarr; above nominal' if anti else ''}</td>"
            f"<td class='num good'>{fmt(b)}</td></tr>"
        )
    return "\n".join(out)


def git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        return "unknown"


def build() -> Path:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    (OUT / "figures").mkdir()
    for figure in sorted(RESULTS.glob("*.png")):
        shutil.copy2(figure, OUT / "figures" / figure.name)

    transcript = capture_transcript()
    binding = capture_key_binding()

    from pqfw import pqc

    alg = pqc.alg_report()
    built = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    template = (Path(__file__).parent / "static_template.html").read_text(encoding="utf-8")
    page = template
    replacements = {
        "{{BUILT}}": built,
        "{{COMMIT}}": git_commit(),
        "{{KEM}}": alg["kem"],
        "{{SIG}}": alg["sig"],
        "{{AEAD}}": alg["aead"],
        "{{HASH}}": alg["hash"],
        "{{LIBOQS}}": alg["liboqs"],
        "{{T_ENROLL}}": html.escape(transcript["enroll"]),
        "{{T_PROTECT}}": html.escape(transcript["protect"]),
        "{{T_OPEN}}": html.escape(transcript["open"]),
        "{{T_TRACE}}": html.escape(transcript["trace"]),
        "{{T_TAMPER}}": html.escape(transcript["tamper"]),
        "{{T_TRACE_TAMPERED}}": html.escape(transcript["trace_after_tamper"]),
        "{{T_BINDING}}": html.escape(binding),
        "{{ATTACK_ROWS}}": attack_rows(),
        "{{COALITION_ROWS}}": coalition_rows(),
        "{{FP_ROWS}}": fp_rows(),
    }
    for key, value in replacements.items():
        page = page.replace(key, value)

    left = [k for k in replacements if k in page]
    if left:
        raise SystemExit(f"template placeholders left unfilled: {left}")

    (OUT / "index.html").write_text(page, encoding="utf-8")
    (OUT / ".gitattributes").write_text("* -text\n", encoding="utf-8")
    shutil.copy2(Path(__file__).parent / "STATIC_README.md", OUT / "README.md")
    return OUT


if __name__ == "__main__":
    out = build()
    files = sorted(p for p in out.rglob("*") if p.is_file())
    for p in files:
        print(f"  {p.relative_to(out).as_posix():<40} {p.stat().st_size:>9,} B")
    print(f"\n{len(files)} files in {out}")
