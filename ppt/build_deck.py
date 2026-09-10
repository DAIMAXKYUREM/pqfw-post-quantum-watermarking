"""Fill the official SIH 2026 template with Team NOX's PQFW submission.

The template is mandatory and its section prompts may not be reworded, so this edits the
provided deck rather than building one: the SIH chrome (logo, blue footer bar, team
oval, title placeholders) is left exactly as issued, the generic instruction text box on
each content slide is removed, and designed content is laid out in its place.

Layout follows how these decks are actually marked. The architecture slide carries an
end-to-end dataflow diagram rather than a description of one, every claim that can be a
measured number is a measured number, and the visual system in design.py gives the deck
a centre of gravity instead of an even field of identical cards.

    python ppt/fetch_logos.py     # once, to pull the tech marks
    python ppt/build_deck.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from pptx import Presentation
from pptx.enum.text import PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from design import (  # noqa: E402
    AMBER, BODY, CARD, CARD_EDGE, CYAN, FAINT, GREEN, GREEN_BRIGHT, INK, LEFT, MINT,
    MINT_EDGE, MUTED, NAVY, NAVY_DEEP, ON_DARK_DIM, ORANGE, RED, RIGHT, ROSE, ROSE_EDGE,
    TOP, WARM, WARM_EDGE, WHITE, bullets, flow_arrow, flow_arrow_down, heading, hexbadge,
    bring_to_front, label, logo, node, panel, para, rect, rich, stat, textbox,
)

TEMPLATE = ROOT / "template.pptx"
OUT = ROOT / "NOX_SIH2026_PQFW.pptx"
LOGOS = ROOT / "logos"

PS_ID = "SIH26237"
PS_TITLE = ("Cryptographic Attribution and Immutable Decryption Provenance for "
            "Multi-Recipient Encrypted Document Distribution")
ORG = "Ministry of Defence"
THEME = "Blockchain & Cybersecurity"
TEAM_ID = "—  (to be assigned on the portal)"
TEAM_NAME = "NOX"
INSTITUTE = "International Institute of Information Technology, Bhubaneswar"
MEMBERS = ["Alok Ranjan Tripathy", "Subhashree Dash", "Krishna Mohanty",
           "Tanisth Das", "Bineet Lenka", "Shreyas Changder"]
LIVE = "pqfw.onrender.com"
RESULTS = "evildeity-pqfw-post-quantum-watermarking.static.hf.space"


NOTES = {
    1: ("Problem statement SIH26237, Ministry of Defence. One document goes to many "
        "cleared recipients; it leaks; today every one of them is an equally plausible "
        "suspect. We built PQFW, and it is running right now at the address on this "
        "slide — scan the code and follow along."),
    2: ("The core idea in one sentence: the fingerprint is a consequence of which "
        "decryption keys you hold, not of software choosing to add a watermark. Each "
        "mark slot is written two ways that look identical and encrypted under different "
        "keys; you get one key per slot. The other rendering is an AES-GCM tag failure "
        "for you. There is no unmarked copy anywhere — not even on our own disk. Bottom "
        "left is a real verdict from the running system."),
    3: ("Three stages, all offline. Distribute: one ciphertext for everybody plus a 14 KB "
        "key bundle each. Decrypt: the recipient spends one credential, gets a uniquely "
        "marked copy, and signs an ML-DSA-65 receipt with their own key — that is the "
        "non-repudiation. Record: three validators independently verify that receipt and "
        "commit it 2-of-3. Trace: extract the marks, score them, check the ledger. No "
        "cloud KMS, no public chain, no network call at any point."),
    4: ("We are honest about what breaks it. Retyping, OCR and stripping invisible "
        "characters defeat the text carrier, and inserting a word desynchronises the "
        "slots — all four are measured and published rather than hidden. The point is the "
        "failure mode: when an attack wins the system fails to identify anybody. "
        "Misidentification stayed at zero across the whole erasure sweep. The bottom row "
        "is the actual next four steps, not an aspiration."),
    5: ("Ministry of Defence context: service HQ, procurement, DRDO and partners, "
        "inter-agency sharing. The real product is deterrence — when every holder knows "
        "their copy is individually accountable, most leaks never happen. And it protects "
        "the accused as much as it exposes the leaker: a stated error probability and a "
        "refusal to guess are what stop an innocent officer being named."),
    6: ("Every requirement in the problem statement, and every one is exercised by an "
        "automated test and by a step of the live demo — 163 tests. Two things we do not "
        "claim: this proves traceability, not unframeability, because the distributor "
        "knows the codewords; and post-quantum asymmetric fingerprinting has no drop-in "
        "construction yet, so we say so rather than pretending. Scan the code and try to "
        "break it."),
}


# --- template plumbing ----------------------------------------------------------


def drop(shape):
    shape._element.getparent().remove(shape._element)


def find(slide, name):
    for shape in slide.shapes:
        if shape.name == name:
            return shape
    return None


def set_title(slide, text, size=None):
    title = find(slide, "Title 1")
    if title is None:
        return
    p = title.text_frame.paragraphs[0]
    for run in list(p.runs)[1:]:
        run._r.getparent().remove(run._r)
    if p.runs:
        p.runs[0].text = text
        if size is not None:
            p.runs[0].font.size = Pt(size)


def set_team_oval(slide):
    for name in ("Oval 8", "Oval 9", "Oval 10", "Oval 11"):
        oval = find(slide, name)
        if oval is None:
            continue
        oval.fill.solid()
        oval.fill.fore_color.rgb = NAVY_DEEP
        oval.line.color.rgb = ORANGE
        oval.line.width = Pt(1.5)
        tf = oval.text_frame
        tf.clear()
        p = tf.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        run = p.add_run()
        run.text = TEAM_NAME
        run.font.size = Pt(15)
        run.font.bold = True
        run.font.color.rgb = WHITE
        run.font.name = BODY


def logo_row(slide, x, y, size, gap, marks):
    """Tech marks in one colour. Recognisable by shape, not by eight brand hues."""
    cx = x
    for name, caption in marks:
        path = LOGOS / f"{name}.png"
        if path.exists():
            logo(slide, path, cx, y, size)
        tf = textbox(slide, cx - 0.15, y + size + 0.05, size + 0.30, 0.18)
        para(tf, caption, size=6.2, color=FAINT, space_after=0, first=True,
             align=PP_ALIGN.CENTER)
        cx += size + gap
    return cx


# --- slides -----------------------------------------------------------------------


def slide1(slide):
    drop(find(slide, "TextBox 9"))

    # A dark field under the title band gives the opening slide a centre of gravity.
    # It starts below the title so the template's own navy wordmark stays legible.
    panel(slide, 0.0, 1.02, 7.62, 6.48, NAVY_DEEP, radius=0.0)
    rect(slide, 0.0, 1.02, 7.62, 0.055, ORANGE, radius=0.0)

    subtitle = find(slide, "Subtitle 3")
    if subtitle is not None:
        subtitle.left, subtitle.top = Inches(0.62), Inches(1.30)
        subtitle.width, subtitle.height = Inches(6.6), Inches(1.16)
        tf = subtitle.text_frame
        tf.clear()
        tf.margin_left = tf.margin_right = Emu(0)
        para(tf, "PQFW", size=46, bold=True, color=WHITE, space_after=0, first=True)
        para(tf, "Post-Quantum Forensic Watermarking", size=14.5, bold=True,
             color=ORANGE, space_after=0)
        bring_to_front(subtitle)

    tf = textbox(slide, 0.62, 2.60, 6.6, 2.5)
    rows = [
        ("Problem Statement ID", PS_ID),
        ("Problem Statement Title", PS_TITLE),
        ("Organisation", ORG),
        ("Theme", THEME),
        ("PS Category", "Software"),
        ("Team ID", TEAM_ID),
        ("Team Name", f"{TEAM_NAME}  ·  {INSTITUTE}"),
    ]
    for i, (key, value) in enumerate(rows):
        rich(tf, [(key + "   ", False, ON_DARK_DIM), (value, True, WHITE)],
             size=9.8, space_after=5, first=(i == 0))

    # scannable from the back of the room
    rect(slide, 0.62, 5.26, 6.6, 1.24, WHITE, edge=ORANGE, radius=0.06, line_w=1.5)
    qr = ROOT / "qr_live.png"
    if qr.exists():
        logo(slide, qr, 0.78, 5.42, 0.92)
    tf = textbox(slide, 1.86, 5.44, 5.22, 0.92)
    para(tf, "LIVE WORKING PROTOTYPE  ·  SCAN IT", size=8, bold=True, color=GREEN,
         space_after=2.5, first=True, spacing=1.2)
    para(tf, LIVE, size=14, bold=True, color=NAVY_DEEP, space_after=2.5)
    para(tf, "Real ML-KEM-768 / ML-DSA-65 computed server-side.  Evaluation and attack "
             "results: " + RESULTS, size=7, color=MUTED, space_after=0)

    tf = textbox(slide, 0.62, 6.64, 6.6, 0.5)
    para(tf, "TEAM MEMBERS", size=7, bold=True, color=ON_DARK_DIM, space_after=2.5,
         first=True, spacing=1.4)
    para(tf, "  ·  ".join(MEMBERS), size=8.2, color=WHITE, space_after=0)


def slide2(slide):
    drop(find(slide, "TextBox 8"))
    set_title(slide, "PQFW — A LEAK THAT NAMES ITSELF", size=25)

    heading(slide, LEFT, TOP, 7.9, "1",
            "Proposed Solution (Describe your Idea/Solution/Prototype)")

    panel(slide, LEFT, TOP + 0.42, 7.9, 1.84)
    label(slide, LEFT + 0.22, TOP + 0.54, 5.4,
          "Detailed explanation of the proposed solution", color=ON_DARK_DIM)

    y = TOP + 0.82
    bw, gap = 1.70, 0.32
    xs = [LEFT + 0.22 + i * (bw + gap) for i in range(4)]
    node(slide, xs[0], y, bw, 1.28, "Split the document",
         ["base body", "+ m invisible", "mark slots"], "ghost")
    flow_arrow(slide, xs[0] + bw + 0.03, y + 0.64, gap - 0.06, ORANGE)
    node(slide, xs[1], y, bw, 1.28, "Two renderings, two keys",
         ["identical to read,", "encrypted under", "different keys"], "accent")
    flow_arrow(slide, xs[1] + bw + 0.03, y + 0.64, gap - 0.06)
    node(slide, xs[2], y, bw, 1.28, "One ciphertext",
         ["broadcast to all N,", "byte-identical", "for everybody"], "dark")
    flow_arrow(slide, xs[2] + bw + 0.03, y + 0.64, gap - 0.06, GREEN_BRIGHT)
    node(slide, xs[3], y, bw, 1.28, "One key each",
         ["recipient holds", "1 of the 2 keys", "per slot"], "good")

    tf = textbox(slide, LEFT, TOP + 2.36, 7.9, 0.46)
    rich(tf, [("The fingerprint is not something their software chose to add — it is a "
               "consequence of ", False, INK),
              ("which keys they hold", True, NAVY),
              (". The other rendering is an AES-GCM tag failure for them, and ", False, INK),
              ("no unmarked copy exists anywhere", True, NAVY),
              (" — not in the package, not in transit, not on the sender's disk.",
               False, INK)],
         size=9.4, space_after=0, first=True)

    heading(slide, LEFT, TOP + 2.90, 7.9, "2", "How it addresses the problem")
    tf = textbox(slide, LEFT + 0.02, TOP + 3.30, 7.88, 1.0)
    bullets(tf, [
        "Today every cleared recipient is an equally plausible suspect — the decrypted "
        "bytes are identical for all of them.",
        "PQFW makes each copy forensically distinct while visually identical: a leak "
        "resolves to one recipient and one decryption session.",
        "Access logs can be edited by an administrator; a static watermark is the same "
        "for everyone. Both are replaced, not patched.",
    ], size=9.3, gap=4.5)

    ey = TOP + 4.10
    heading(slide, LEFT, ey, 7.9, "3", "What the system actually returns")
    rect(slide, LEFT, ey + 0.40, 7.9, 1.00, NAVY_DEEP, edge=GREEN_BRIGHT, radius=0.06,
         line_w=1.75)
    tf = textbox(slide, LEFT + 0.24, ey + 0.54, 4.4, 0.72)
    rich(tf, [("IDENTIFIED", True, GREEN_BRIGHT), ("    r07, session #0", True, WHITE)],
         size=14, space_after=3, first=True)
    para(tf, "false-accusation probability at most 2.8 × 10⁻⁵⁹", size=8.5,
         color=ON_DARK_DIM, space_after=4)
    para(tf, "2 KB memo · 20 recipients · 301 mark slots · next suspect 10σ behind",
         size=7.1, color=ON_DARK_DIM, space_after=0)

    checks = ["statistical significance (provable bound < α)",
              "the accused's own ML-DSA-65 receipt verifies",
              "ledger hash chain intact",
              "block committed by 2 of 3 validators",
              "Merkle inclusion proof to the signed root"]
    tf = textbox(slide, LEFT + 4.92, ey + 0.52, 3.3, 0.88)
    for i, check in enumerate(checks):
        rich(tf, [("✓  ", True, GREEN_BRIGHT), (check, False, ON_DARK_DIM)],
             size=7.3, space_after=1.4, first=(i == 0))

    rx, rw = 8.55, 4.38
    heading(slide, rx, TOP, rw, "4", "Innovation and uniqueness of the solution")
    cards = [
        ("Enforced by keys, not software",
         "Patching the client does not help. There is no code path around a tag check."),
        ("A provable error bound",
         "Chernoff bound from the code's own biases — not the Gaussian p-value, which we "
         "measured as anti-conservative."),
        ("It refuses to guess",
         "When evidence is thin the verdict is NO IDENTIFICATION — never the wrong person."),
        ("Session-level attribution",
         "Two opens by one person give two fingerprints and two ledger records."),
    ]
    cy = TOP + 0.42
    for i, (title, body) in enumerate(cards):
        rect(slide, rx, cy, rw, 0.92, CARD, edge=CARD_EDGE, radius=0.07, line_w=1.25)
        hexbadge(slide, rx + 0.17, cy + 0.30, 0.26, str(i + 1), fill=NAVY, fsize=8.5)
        tf = textbox(slide, rx + 0.60, cy + 0.14, rw - 0.78, 0.68)
        para(tf, title, size=9.5, bold=True, color=NAVY, space_after=2, first=True)
        para(tf, body, size=8.0, color=MUTED, space_after=0)
        cy += 1.02

    rect(slide, rx, cy + 0.10, rw, 0.86, NAVY_DEEP, edge=ORANGE, radius=0.07, line_w=1.5)
    tf = textbox(slide, rx + 0.20, cy + 0.22, rw - 0.4, 0.66)
    para(tf, "NOT A CONCEPT — IT IS RUNNING", size=7.4, bold=True, color=ORANGE,
         space_after=3, first=True, spacing=1.2)
    rich(tf, [(LIVE, True, WHITE), ("     163 automated tests", False, ON_DARK_DIM)],
         size=10.5, space_after=0)


def slide3(slide):
    """The architecture slide, which is the one that gets marked hardest."""
    drop(find(slide, "TextBox 8"))
    set_title(slide, "TECHNICAL APPROACH")

    dw = 8.66
    panel(slide, LEFT, TOP, dw, 5.46)
    rect(slide, LEFT, TOP, dw, 0.055, ORANGE, radius=0.0)

    tf = textbox(slide, LEFT + 0.22, TOP + 0.18, 6.0, 0.42)
    para(tf, "End-to-end flow", size=12, bold=True, color=WHITE, space_after=1,
         first=True)
    para(tf, "distribute · decrypt & record · trace — every stage runs offline",
         size=8, italic=True, color=ON_DARK_DIM, space_after=0)

    bw, bh, gap = 1.88, 0.92, 0.28
    xs = [LEFT + 0.36 + i * (bw + gap) for i in range(4)]

    def stage(y, number, name, color):
        hexbadge(slide, LEFT + 0.22, y - 0.31, 0.26, number, fill=color, fsize=8.5)
        tf = textbox(slide, LEFT + 0.60, y - 0.30, 5.0, 0.2)
        para(tf, name, size=7.6, bold=True, color=color, space_after=0, first=True,
             caps=True, spacing=1.4)

    y1 = TOP + 1.00
    stage(y1, "1", "Distribute", ORANGE)
    node(slide, xs[0], y1, bw, bh, "Sender's document",
         ["split into base +", "m mark slots"], "ghost")
    flow_arrow(slide, xs[0] + bw + 0.02, y1 + bh / 2, gap - 0.04)
    node(slide, xs[1], y1, bw, bh, "Variant encryption",
         ["AES-256-GCM, a different", "key per rendering"], "accent")
    flow_arrow(slide, xs[1] + bw + 0.02, y1 + bh / 2, gap - 0.04)
    node(slide, xs[2], y1, bw, bh, "Key bundles",
         ["wrapped with ML-KEM-768,", "one key per slot each"], "dark")
    flow_arrow(slide, xs[2] + bw + 0.02, y1 + bh / 2, gap - 0.04)
    node(slide, xs[3], y1, bw, bh, "One package",
         ["identical ciphertext", "for all N recipients"], "dark")
    flow_arrow_down(slide, LEFT + dw / 2, y1 + bh + 0.04, 0.30)

    y2 = y1 + bh + 0.60
    stage(y2, "2", "Decrypt & record", GREEN_BRIGHT)
    node(slide, xs[0], y2, bw, bh, "Recipient decrypts",
         ["unwraps bundle,", "spends one session"], "dark")
    flow_arrow(slide, xs[0] + bw + 0.02, y2 + bh / 2, gap - 0.04, GREEN_BRIGHT)
    node(slide, xs[1], y2, bw, bh, "Uniquely marked copy",
         ["one rendering per slot;", "the other is a tag failure"], "good")
    flow_arrow(slide, xs[1] + bw + 0.02, y2 + bh / 2, gap - 0.04, GREEN_BRIGHT)
    node(slide, xs[2], y2, bw, bh, "Signed receipt",
         ["ML-DSA-65, the recipient's", "own private key"], "good")
    flow_arrow(slide, xs[2] + bw + 0.02, y2 + bh / 2, gap - 0.04, GREEN_BRIGHT)
    node(slide, xs[3], y2, bw, bh, "Distributed ledger",
         ["3 validator replicas,", "2-of-3 block commit"], "good")
    flow_arrow_down(slide, LEFT + dw / 2, y2 + bh + 0.04, 0.30)

    y3 = y2 + bh + 0.60
    stage(y3, "3", "Trace a leak", CYAN)
    node(slide, xs[0], y3, bw, bh, "Leaked copy", ["extract the slot bits"], "ghost")
    flow_arrow(slide, xs[0] + bw + 0.02, y3 + bh / 2, gap - 0.04, CYAN)
    node(slide, xs[1], y3, bw, bh, "Tardos scoring",
         ["score against every", "issued codeword"], "dark")
    flow_arrow(slide, xs[1] + bw + 0.02, y3 + bh / 2, gap - 0.04, CYAN)
    node(slide, xs[2], y3, bw, bh, "Ledger lookup",
         ["commitment → receipt,", "signature + quorum checked"], "dark")
    flow_arrow(slide, xs[2] + bw + 0.02, y3 + bh / 2, gap - 0.04, ORANGE)
    node(slide, xs[3], y3, bw, bh, "Verifiable verdict",
         ["recipient + session", "+ provable error bound"], "accent")

    tf = textbox(slide, LEFT + 0.22, y3 + bh + 0.16, dw - 0.44, 0.22)
    rich(tf, [("Offline and air-gapped throughout — ", True, ORANGE),
              ("no cloud KMS, no public blockchain, no network call at any stage, "
               "asserted by a test that refuses every socket operation.", False,
               ON_DARK_DIM)],
         size=8, space_after=0, first=True)

    rx, rw = 9.32, 3.61
    heading(slide, rx, TOP, rw, "T", "Technologies to be used")
    logo_row(slide, rx + 0.10, TOP + 0.48, 0.40, 0.29,
             [("python", "Python"), ("fastapi", "FastAPI"), ("numpy", "NumPy"),
              ("docker", "Docker"), ("linux", "Linux")])
    logo_row(slide, rx + 0.10, TOP + 1.14, 0.40, 0.29,
             [("pytest", "pytest"), ("github", "GitHub"), ("render", "Render"),
              ("huggingface", "HF"), ("bash", "Bash")])

    tf = textbox(slide, rx, TOP + 1.86, rw, 1.5)
    for i, (key, value) in enumerate([
        ("Key exchange", "ML-KEM-768  ·  FIPS 203"),
        ("Signatures", "ML-DSA-65  ·  FIPS 204"),
        ("PQC library", "liboqs 0.16.0 (Open Quantum Safe)"),
        ("Content", "AES-256-GCM  ·  HKDF-SHA3-256"),
        ("Fingerprint", "symmetric Tardos code (Škorić)"),
        ("Ledger", "hash chain + Merkle blocks, 2-of-3"),
        ("Carriers", "zero-width space  ·  PDF kerning"),
    ]):
        rich(tf, [(key + "   ", True, NAVY), (value, False, INK)], size=8.2,
             space_after=2.5, first=(i == 0))

    heading(slide, rx, TOP + 3.48, rw, "M",
            "Methodology and process for implementation")
    tf = textbox(slide, rx, TOP + 3.90, rw, 1.3)
    bullets(tf, [
        "Safety and audit layers built and tested before any tracing existed.",
        "Test-first: 163 tests, including the central claim that a recipient cannot "
        "decrypt the other variant.",
        "Every attack on the carrier measured and published — including the four that "
        "defeat it.",
    ], size=8.2, gap=3.4)

    rect(slide, rx, TOP + 5.00, rw, 0.36, MINT, edge=MINT_EDGE, radius=0.07, line_w=1.25)
    tf = textbox(slide, rx + 0.14, TOP + 5.08, rw - 0.28, 0.24)
    para(tf, "Shared ciphertext + a 14 KB bundle each, flat in N.", size=8, bold=True,
         color=GREEN, space_after=0, first=True)


def slide4(slide):
    drop(find(slide, "TextBox 8"))
    set_title(slide, "FEASIBILITY AND VIABILITY")

    colw, gap = 4.03, 0.22
    xs = [LEFT, LEFT + colw + gap, LEFT + 2 * (colw + gap)]
    columns = [
        ("1", "Analysis of the feasibility of the idea", CARD, CARD_EDGE, NAVY, [
            ("Already built and running.", "Not a concept — a working deployment anyone "
                                           "can open right now."),
            ("Runs on commodity CPU.", "No GPU, no HSM. The whole demo fits a free "
                                       "0.1-vCPU tier."),
            ("Zero licensing cost.", "Open-source primitives end to end; "
                                     "NIST-standardised, not bespoke."),
            ("Deploys air-gapped.", "No cloud KMS, no public chain, no outbound call."),
            ("Drops in beside existing flows.", "The sender already encrypts once for "
                                                "many; this replaces that step."),
        ]),
        ("2", "Potential challenges and risks", WARM, WARM_EDGE, AMBER, [
            ("Carrier fragility.", "Retyping, OCR or stripping invisible characters "
                                   "destroys a text watermark."),
            ("Word insertion desynchronises.", "Slot addresses are ordinal, so adding a "
                                               "word shifts every later slot."),
            ("Short documents, weaker codes.", "A memo holds ~300 slots; the Tardos "
                                               "bound asks for far more."),
            ("Unframeability.", "The sender knows every codeword, so this proves "
                                "traceability, not non-framing."),
            ("Collusion.", "Recipients can compare copies and splice them together."),
        ]),
        ("3", "Strategies for overcoming these challenges", MINT, MINT_EDGE, GREEN, [
            ("Publish the attacks that win.", "Each measured with its bit error rate, "
                                              "beside the ones survived."),
            ("Fail safe, not loud.", "When an attack wins the result is a failure to "
                                     "identify — misidentification stayed at 0.0%."),
            ("Report the reachable bound.", "protect states the best error probability "
                                            "the document supports, before sending."),
            ("Tardos codes for collusion.", "Where colluders agree they are stuck — no "
                                            "one holds the other key."),
            ("Content-anchored slots.", "The named next step, replacing ordinal "
                                        "addressing."),
        ]),
    ]
    for x, (num, title, fill, edge, accent, items) in zip(xs, columns):
        heading(slide, x, TOP, colw, num, title)
        rect(slide, x, TOP + 0.44, colw, 2.16, fill, edge=edge, radius=0.06, line_w=1.25)
        tf = textbox(slide, x + 0.16, TOP + 0.56, colw - 0.32, 1.95)
        for i, (head, body) in enumerate(items):
            rich(tf, [(head + " ", True, accent), (body, False, MUTED)], size=8.6,
                 space_after=5.5, first=(i == 0))

    panel(slide, LEFT, TOP + 2.80, RIGHT - LEFT, 1.28)
    label(slide, LEFT + 0.22, TOP + 2.92, 4.0, "Measured, not asserted", color=ORANGE,
          size=7.8)
    figures = [
        ("100%", "coalition of 8 traced at the\nprescribed code length", GREEN_BRIGHT),
        ("0.0%", "misidentification across a\n0–95% erasure sweep", GREEN_BRIGHT),
        ("2.8e-59", "provable false-accusation\nbound on the live demo", WHITE),
        ("0 / 10,000", "innocent trials accused\nat α ≤ 1e-5", GREEN_BRIGHT),
        ("4", "attacks that defeat the\ncarrier — all published", ORANGE),
        ("163", "automated tests,\nall passing", WHITE),
    ]
    sw = (RIGHT - LEFT - 0.44) / len(figures)
    for i, (value, caption, color) in enumerate(figures):
        stat(slide, LEFT + 0.22 + i * sw, TOP + 3.22, sw, value, caption, color=color,
             vsize=18, csize=7.0, on_dark=True)

    heading(slide, LEFT, TOP + 4.26, RIGHT - LEFT, "4", "Path to deployment")
    steps = [
        ("NOW", "Working prototype", "text and PDF carriers, 3-validator ledger, live"),
        ("NEXT", "Content-anchored slots", "removes the word-insertion weakness"),
        ("THEN", "Departmental pilot", "validators held by three separate offices"),
        ("SCALE", "Cross-organisation", "one validator per participating body"),
    ]
    sx = LEFT
    stepw = (RIGHT - LEFT - 3 * 0.34) / 4
    for i, (tag, head, body) in enumerate(steps):
        live = i == 0
        rect(slide, sx, TOP + 4.66, stepw, 0.90, MINT if live else CARD,
             edge=MINT_EDGE if live else CARD_EDGE, radius=0.07, line_w=1.25)
        tf = textbox(slide, sx + 0.16, TOP + 4.76, stepw - 0.32, 0.72)
        para(tf, tag, size=6.8, bold=True, color=GREEN if live else FAINT,
             space_after=1.5, first=True, spacing=1.4)
        para(tf, head, size=9.4, bold=True, color=NAVY, space_after=1.5)
        para(tf, body, size=7.6, color=MUTED, space_after=0)
        if i < 3:
            flow_arrow(slide, sx + stepw + 0.05, TOP + 5.11, 0.24, NAVY)
        sx += stepw + 0.34


def slide5(slide):
    drop(find(slide, "TextBox 8"))
    set_title(slide, "IMPACT AND BENEFITS")

    colw = 6.24
    x2 = LEFT + colw + 0.29

    heading(slide, LEFT, TOP, colw, "1", "Potential impact on the target audience")
    rect(slide, LEFT, TOP + 0.44, colw, 1.86, CARD, edge=CARD_EDGE, radius=0.06,
         line_w=1.25)
    tf = textbox(slide, LEFT + 0.18, TOP + 0.56, colw - 0.36, 1.7)
    for i, (head, body) in enumerate([
        ("Service headquarters.", "Operational orders and classified assessments become "
                                  "individually accountable, not collectively deniable."),
        ("Defence procurement.", "Tender documents and technical specifications reach "
                                 "vendors traceably; a pre-bid leak has an owner."),
        ("DRDO and defence PSUs.", "Design data shared with partners and contractors "
                                   "carries a non-repudiable receipt per recipient."),
        ("Inter-agency sharing.", "Intelligence keeps its provenance without a central "
                                  "authority anyone has to trust."),
    ]):
        rich(tf, [(head + " ", True, NAVY), (body, False, MUTED)], size=9.4,
             space_after=8, first=(i == 0))

    heading(slide, x2, TOP, colw, "2",
            "Benefits of the solution (social, economic, environmental)")
    rect(slide, x2, TOP + 0.44, colw, 1.86, MINT, edge=MINT_EDGE, radius=0.06,
         line_w=1.25)
    tf = textbox(slide, x2 + 0.18, TOP + 0.56, colw - 0.36, 1.7)
    for i, (head, body) in enumerate([
        ("Deterrence is the real product.", "When every holder knows their copy is "
                                            "individually accountable, most leaks never "
                                            "happen."),
        ("Protects the accused too.", "A stated error probability and a refusal to guess "
                                      "are what stop an innocent officer being named."),
        ("Zero licensing cost.", "Open-source and free-tier; per-department rollout cost "
                                 "is effectively nil."),
        ("Quantum-durable.", "A defence assessment stays sensitive for decades; FIPS "
                             "203/204 resist harvest-now-decrypt-later."),
        ("Scales unchanged.", "Any organisation distributing to a named list — only the "
                              "list changes."),
    ]):
        rich(tf, [(head + " ", True, GREEN), (body, False, MUTED)], size=9.0,
             space_after=4.5, first=(i == 0))

    heading(slide, LEFT, TOP + 2.46, RIGHT - LEFT, "3", "What changes")
    # 1.34in left a visible half-inch of dead card under the third bullet; the pair is
    # sized to its content and the space handed to the cost band instead.
    y = TOP + 2.86
    rect(slide, LEFT, y, colw, 0.84, ROSE, edge=ROSE_EDGE, radius=0.06, line_w=1.25)
    tf = textbox(slide, LEFT + 0.20, y + 0.13, colw - 0.4, 0.82)
    para(tf, "TODAY", size=8.2, bold=True, color=RED, space_after=5, first=True,
         spacing=1.4)
    bullets(tf, [
        "Every cleared recipient is an equally plausible suspect.",
        "Access logs can be edited by the administrator who holds them.",
        "One identical watermark for all recipients attributes nothing.",
    ], size=8.6, gap=3, color=MUTED)

    rect(slide, x2, y, colw, 0.84, NAVY_DEEP, edge=GREEN_BRIGHT, radius=0.06, line_w=1.5)
    tf = textbox(slide, x2 + 0.20, y + 0.13, colw - 0.4, 0.82)
    para(tf, "WITH PQFW", size=8.2, bold=True, color=GREEN_BRIGHT, space_after=5,
         first=True, spacing=1.4)
    bullets(tf, [
        "A leaked copy names one recipient and one decryption session.",
        "Records replicated 3 ways; one compromised admin is out-voted.",
        "Every copy distinct, and the accusation carries a provable bound.",
    ], size=8.6, gap=3, color=ON_DARK_DIM)

    heading(slide, LEFT, y + 1.04, RIGHT - LEFT, "4", "Cost of running it",
            "measured on the running prototype, not projected")
    panel(slide, LEFT, y + 1.50, RIGHT - LEFT, 1.12)
    numbers = [
        ("116 KB", "shared ciphertext —\nthe same bytes for everyone", WHITE),
        ("34 KB", "per recipient, and\nindependent of N", WHITE),
        ("0", "GPUs, HSMs and\ncloud services required", GREEN_BRIGHT),
        ("₹0", "licensing cost —\nopen-source throughout", GREEN_BRIGHT),
        ("< 1 s", "to trace a leak against\n1,000 recipients", ORANGE),
    ]
    nw = (RIGHT - LEFT - 0.4) / len(numbers)
    for i, (value, caption, color) in enumerate(numbers):
        # 0.28in of optical margin either side of the 0.57in stat block, so the
        # numbers sit in the middle of the band rather than riding its top edge.
        stat(slide, LEFT + 0.20 + i * nw, y + 1.78, nw, value, caption, color=color,
             vsize=19, csize=7.1, on_dark=True)


def slide6(slide):
    drop(find(slide, "TextBox 8"))
    set_title(slide, "RESEARCH AND REFERENCES")

    colw, gap = 4.03, 0.22
    xs = [LEFT, LEFT + colw + gap, LEFT + 2 * (colw + gap)]

    heading(slide, xs[0], TOP, colw, "1", "Standards and specifications")
    tf = textbox(slide, xs[0], TOP + 0.44, colw, 2.6)
    for i, (key, body) in enumerate([
        ("FIPS 203 (2024)", "Module-Lattice-Based Key-Encapsulation Mechanism — ML-KEM. "
                            "NIST."),
        ("FIPS 204 (2024)", "Module-Lattice-Based Digital Signature Standard — ML-DSA. "
                            "NIST."),
        ("FIPS 202", "SHA-3 permutation-based hash and extendable-output functions."),
        ("NIST SP 800-38D", "Galois/Counter Mode for AES, used for every ciphertext "
                            "here."),
    ]):
        rich(tf, [(key + "  ", True, NAVY), (body, False, MUTED)], size=9.2,
             space_after=13, first=(i == 0))

    heading(slide, xs[1], TOP, colw, "2", "Methods and literature")
    tf = textbox(slide, xs[1], TOP + 0.44, colw, 2.6)
    for i, (key, body) in enumerate([
        ("Tardos (2003)", "Optimal probabilistic fingerprint codes. STOC."),
        ("Škorić et al. (2008)", "Symmetric Tardos fingerprinting codes. Designs, Codes "
                                 "and Cryptography."),
        ("Boneh & Shaw (1998)", "Collusion-secure fingerprinting for digital data. IEEE "
                                "Trans. Inf. Theory."),
        ("Open Quantum Safe", "liboqs — the C library providing both mechanisms used "
                              "here."),
        ("Brakerski–Fan–Vercauteren", "Somewhat-homomorphic encryption; the route to "
                                      "post-quantum asymmetric fingerprinting. Future "
                                      "work."),
    ]):
        rich(tf, [(key + "  ", True, NAVY), (body, False, MUTED)], size=9.2,
             space_after=9, first=(i == 0))

    heading(slide, xs[2], TOP, colw, "3", "Our work — live and inspectable")
    rect(slide, xs[2], TOP + 0.44, colw, 1.10, NAVY_DEEP, edge=ORANGE, radius=0.07,
         line_w=1.5)
    qr = ROOT / "qr_live.png"
    if qr.exists():
        logo(slide, qr, xs[2] + 0.14, TOP + 0.58, 0.82)
    tf = textbox(slide, xs[2] + 1.08, TOP + 0.60, colw - 1.24, 0.86)
    para(tf, "WORKING PROTOTYPE", size=7, bold=True, color=ORANGE, space_after=3,
         first=True, spacing=1.2)
    para(tf, LIVE, size=11, bold=True, color=WHITE, space_after=3)
    para(tf, "Five guided steps, real post-quantum cryptography server-side.",
         size=7.3, color=ON_DARK_DIM, space_after=0)

    rect(slide, xs[2], TOP + 1.66, colw, 0.96, CARD, edge=CARD_EDGE, radius=0.07,
         line_w=1.25)
    tf = textbox(slide, xs[2] + 0.16, TOP + 1.76, colw - 0.32, 0.8)
    para(tf, "EVALUATION AND ATTACK RESULTS", size=7, bold=True, color=NAVY,
         space_after=3, first=True, spacing=1.2)
    para(tf, RESULTS, size=7.3, bold=True, color=NAVY, space_after=3)
    para(tf, "Every figure produced by executing the library, commit recorded.",
         size=7.3, color=MUTED, space_after=0)

    heading(slide, LEFT, TOP + 3.04, RIGHT - LEFT, "✓",
            f"Every requirement in {PS_ID}, and where it is met",
            "each one exercised by an automated test and by a step of the live demo")
    panel(slide, LEFT, TOP + 3.50, RIGHT - LEFT, 2.02)
    reqs = [
        "Unique invisible forensic watermark at the moment of decryption",
        "Specific to each recipient and each decryption session",
        "Every copy visually identical, forensically distinct",
        "Each decryption cryptographically bound to the recipient's identity",
        "Signature generated with the recipient's own private key",
        "NIST-standardised PQC for key exchange and digital signatures",
        "Immutable audit layer implemented as a distributed ledger",
        "No single administrator or compromised account can alter records",
        "Extract the watermark, match it against the ledger, verify it",
        "Complete operation offline and air-gapped",
        "No dependency on external cloud KMS services",
        "No dependency on public blockchain networks",
    ]
    cw = (RIGHT - LEFT - 0.44) / 2
    for i, text in enumerate(reqs):
        col, row = divmod(i, 6)
        tf = textbox(slide, LEFT + 0.24 + col * cw, TOP + 3.68 + row * 0.300,
                     cw - 0.1, 0.28)
        rich(tf, [("✓  ", True, GREEN_BRIGHT), (text, False, ON_DARK_DIM)], size=8.8,
             space_after=0, first=True)


# ---------------------------------------------------------------------------


def main() -> None:
    prs = Presentation(TEMPLATE)

    # the template's own instructions say to delete the pointers slide before upload
    xml_slides = prs.slides._sldIdLst
    slides = list(xml_slides)
    prs.part.drop_rel(slides[6].rId)
    xml_slides.remove(slides[6])

    for index, build in enumerate([slide1, slide2, slide3, slide4, slide5, slide6]):
        slide = prs.slides[index]
        if index > 0:
            set_team_oval(slide)
        build(slide)
        note = NOTES.get(index + 1)
        if note:
            slide.notes_slide.notes_text_frame.text = note

    prs.save(OUT)
    print(f"wrote {OUT}  ({OUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
