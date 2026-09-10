"""Fill the official SIH 2026 template with Team NOX's PQFW submission.

The template is mandatory and its section prompts may not be reworded, so this edits
the provided deck rather than building one: the SIH chrome (logo, blue footer bar, team
oval, title placeholders) is left exactly as issued, the generic instruction text box on
each content slide is removed, and designed content is laid out in its place.

Two things drive the layout, both from how SIH decks are actually judged: the
architecture slide carries an end-to-end dataflow diagram rather than a description of
one, and every claim that can be a measured number is a measured number.

    python ppt/build_deck.py
"""

from __future__ import annotations

import copy
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parent
TEMPLATE = ROOT / "template.pptx"
OUT = ROOT / "NOX_SIH2026_PQFW.pptx"

# --- identity ---------------------------------------------------------------
PS_ID = "SIH26237"
PS_TITLE = ("Cryptographic Attribution and Immutable Decryption Provenance for "
            "Multi-Recipient Encrypted Document Distribution")
ORG = "Ministry of Defence"
THEME = "Blockchain & Cybersecurity"
TEAM_ID = "—  (to be assigned on the portal)"   # <-- fill once the portal issues it
TEAM_NAME = "NOX"
INSTITUTE = "International Institute of Information Technology, Bhubaneswar"
MEMBERS = [
    "Alok Ranjan Tripathy", "Subhashree Dash", "Krishna Mohanty",
    "Tanisth Das", "Bineet Lenka", "Shreyas Changder",
]
LIVE = "pqfw.onrender.com"
RESULTS = "evildeity-pqfw-post-quantum-watermarking.static.hf.space"

# --- palette ----------------------------------------------------------------
NAVY = RGBColor(0x1F, 0x38, 0x64)
INK = RGBColor(0x20, 0x28, 0x38)
MUTED = RGBColor(0x5A, 0x67, 0x7D)
ORANGE = RGBColor(0xE0, 0x6C, 0x18)
GREEN = RGBColor(0x1B, 0x7F, 0x5E)
RED = RGBColor(0xB4, 0x28, 0x28)
AMBER = RGBColor(0xB0, 0x74, 0x10)
CARD = RGBColor(0xEE, 0xF3, 0xFA)
CARD_EDGE = RGBColor(0xC3, 0xD3, 0xE8)
WARM = RGBColor(0xFD, 0xF3, 0xE2)
WARM_EDGE = RGBColor(0xE8, 0xC9, 0x93)
GOODBG = RGBColor(0xE8, 0xF4, 0xEE)
GOOD_EDGE = RGBColor(0xA8, 0xD3, 0xBF)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

BODY = "Calibri"

# content area between the title band and the blue footer bar
TOP = 1.30
BOTTOM = 6.86
LEFT = 0.42
RIGHT = 12.91



NOTES = {
    1: ("Problem statement SIH26237, Ministry of Defence. One document goes to many "
        "cleared recipients; it leaks; today every one of them is an equally plausible "
        "suspect. We built PQFW, and it is running right now at the address on this "
        "slide — scan the code and follow along."),
    2: ("The core idea in one sentence: the fingerprint is a consequence of which "
        "decryption keys you hold, not of software choosing to add a watermark. Each "
        "mark slot is written two ways that look identical and encrypted under "
        "different keys; you get one key per slot. The other rendering is an AES-GCM "
        "tag failure for you. There is no unmarked copy anywhere — not even on our own "
        "disk. Bottom left is a real verdict from the running system."),
    3: ("Three stages, all offline. Distribute: one ciphertext for everybody, plus a "
        "14 KB key bundle each. Decrypt: the recipient spends one credential, gets a "
        "uniquely marked copy, and signs an ML-DSA-65 receipt with their own key — that "
        "is the non-repudiation. Record: three validators independently verify that "
        "receipt and commit it 2-of-3. Trace: extract the marks, score them, and check "
        "the ledger. No cloud KMS, no public chain, no network call at any point."),
    4: ("We are honest about what breaks it. Retyping, OCR and stripping invisible "
        "characters defeat the text carrier, and inserting a word desynchronises the "
        "slots — all four are measured and published rather than hidden. The point is "
        "the failure mode: when an attack wins the system fails to identify anybody. "
        "Misidentification stayed at zero across the whole erasure sweep. The bottom row "
        "is the actual next four steps, not an aspiration."),
    5: ("Ministry of Defence context: service HQ, procurement, DRDO and partners, "
        "inter-agency sharing. The real product is deterrence — when every holder knows "
        "their copy is individually accountable, most leaks never happen. And it "
        "protects the accused as much as it exposes the leaker: a stated error "
        "probability and a refusal to guess are what stop an innocent officer being "
        "named. Costs nothing to run."),
    6: ("Every requirement in the problem statement, and every one is exercised by an "
        "automated test and by a step of the live demo — 163 tests. Two things we do "
        "not claim: this proves traceability, not unframeability, because the "
        "distributor knows the codewords; post-quantum asymmetric fingerprinting has no "
        "drop-in construction yet and we say so rather than pretending. Scan the code "
        "and try to break it."),
}

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def drop(shape) -> None:
    shape._element.getparent().remove(shape._element)


def find(slide, name: str):
    for shape in slide.shapes:
        if shape.name == name:
            return shape
    return None


def card(slide, x, y, w, h, fill=CARD, edge=CARD_EDGE, radius=0.045):
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y),
                                 Inches(w), Inches(h))
    box.adjustments[0] = radius
    box.fill.solid()
    box.fill.fore_color.rgb = fill
    box.line.color.rgb = edge
    box.line.width = Pt(0.75)
    box.shadow.inherit = False
    if box.has_text_frame:
        box.text_frame.clear()
    return box


def textbox(slide, x, y, w, h, anchor=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = box.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = Emu(0)
    tf.margin_top = tf.margin_bottom = Emu(0)
    return tf


def para(tf, text, size=10.5, bold=False, color=INK, space_after=3, first=False,
         align=PP_ALIGN.LEFT, italic=False, font=BODY, space_before=0):
    p = tf.paragraphs[0] if first else tf.add_paragraph()
    p.alignment = align
    p.space_after = Pt(space_after)
    p.space_before = Pt(space_before)
    run = p.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.italic = italic
    run.font.color.rgb = color
    run.font.name = font
    return p


def rich(tf, parts, size=10.5, space_after=3, first=False, align=PP_ALIGN.LEFT,
         space_before=0):
    """One paragraph, several differently styled runs: ('text', bold, colour)."""
    p = tf.paragraphs[0] if first else tf.add_paragraph()
    p.alignment = align
    p.space_after = Pt(space_after)
    p.space_before = Pt(space_before)
    for text, bold, color in parts:
        run = p.add_run()
        run.text = text
        run.font.size = Pt(size)
        run.font.bold = bold
        run.font.color.rgb = color
        run.font.name = BODY
    return p


def bullets(tf, items, size=10.5, color=INK, gap=3.5, marker="▪  "):
    for text in items:
        para(tf, marker + text, size=size, color=color, space_after=gap)


def section(slide, x, y, w, title, kicker=None):
    """A section prompt from the template, rendered as a heading."""
    tf = textbox(slide, x, y, w, 0.30)
    para(tf, title, size=11.5, bold=True, color=NAVY, space_after=0, first=True)
    if kicker:
        para(tf, kicker, size=8.5, italic=True, color=MUTED, space_after=0)
    return tf


def flowbox(slide, x, y, w, h, title, lines, fill=CARD, edge=CARD_EDGE,
            title_color=NAVY, tsize=8.6, lsize=7.0):
    card(slide, x, y, w, h, fill=fill, edge=edge, radius=0.08)
    tf = textbox(slide, x + 0.07, y + 0.07, w - 0.14, h - 0.14, anchor=MSO_ANCHOR.MIDDLE)
    para(tf, title, size=tsize, bold=True, color=title_color, space_after=1.5,
         first=True, align=PP_ALIGN.CENTER)
    for line in lines:
        para(tf, line, size=lsize, color=MUTED, space_after=0.5, align=PP_ALIGN.CENTER)


def arrow(slide, x, y, w=0.22, color=NAVY):
    a = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, Inches(x), Inches(y - 0.055),
                               Inches(w), Inches(0.11))
    a.fill.solid()
    a.fill.fore_color.rgb = color
    a.line.fill.background()
    a.shadow.inherit = False
    if a.has_text_frame:
        a.text_frame.clear()
    return a


def down_arrow(slide, x, y, h=0.2, color=NAVY):
    a = slide.shapes.add_shape(MSO_SHAPE.DOWN_ARROW, Inches(x - 0.055), Inches(y),
                               Inches(0.11), Inches(h))
    a.fill.solid()
    a.fill.fore_color.rgb = color
    a.line.fill.background()
    a.shadow.inherit = False
    if a.has_text_frame:
        a.text_frame.clear()
    return a


def stat(slide, x, y, w, value, label, color=NAVY, vsize=19):
    tf = textbox(slide, x, y, w, 0.72, anchor=MSO_ANCHOR.TOP)
    para(tf, value, size=vsize, bold=True, color=color, space_after=0, first=True,
         align=PP_ALIGN.CENTER)
    para(tf, label, size=7.6, color=MUTED, space_after=0, align=PP_ALIGN.CENTER)


def set_title(slide, text, size=None):
    title = find(slide, "Title 1")
    if title is None:
        return
    tf = title.text_frame
    p = tf.paragraphs[0]
    for run in list(p.runs)[1:]:
        run._r.getparent().remove(run._r)
    if p.runs:
        p.runs[0].text = text
        if size is not None:
            p.runs[0].font.size = Pt(size)
    else:
        para(tf, text, size=size or 28, bold=True, color=NAVY, first=True,
             align=PP_ALIGN.CENTER)


def set_team_oval(slide):
    for name in ("Oval 8", "Oval 9", "Oval 10", "Oval 11"):
        oval = find(slide, name)
        if oval is None:
            continue
        tf = oval.text_frame
        tf.clear()
        p = tf.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        run = p.add_run()
        run.text = TEAM_NAME
        run.font.size = Pt(15)
        run.font.bold = True
        run.font.color.rgb = NAVY
        run.font.name = BODY


# ---------------------------------------------------------------------------
# slides
# ---------------------------------------------------------------------------


def slide1(slide):
    """Title page. Keeps the template's own prompt labels."""
    drop(find(slide, "TextBox 9"))
    subtitle = find(slide, "Subtitle 3")
    if subtitle is not None:
        # The template centres this under a title that sits at y=-0.58, so the default
        # position collides with "SMART INDIA HACKATHON 2026". Move it into the free
        # left column instead, clear of both the title and the brain graphic.
        subtitle.left, subtitle.top = Inches(0.42), Inches(1.16)
        subtitle.width, subtitle.height = Inches(6.7), Inches(1.02)
        tf = subtitle.text_frame
        tf.clear()
        tf.margin_left = tf.margin_right = Emu(0)
        para(tf, "PQFW", size=38, bold=True, color=NAVY, space_after=0, first=True,
             align=PP_ALIGN.LEFT)
        para(tf, "Post-Quantum Forensic Watermarking", size=14.5, color=ORANGE,
             space_after=0, align=PP_ALIGN.LEFT, bold=True)

    tf = textbox(slide, 0.42, 2.36, 6.6, 3.3)
    rows = [
        ("Problem Statement ID", PS_ID),
        ("Problem Statement Title", PS_TITLE),
        ("Organisation", ORG),
        ("Theme", THEME),
        ("PS Category", "Software"),
        ("Team ID", TEAM_ID),
        ("Team Name", f"{TEAM_NAME}  ·  {INSTITUTE}"),
    ]
    for i, (label, value) in enumerate(rows):
        p = rich(tf, [(label + "  ", True, MUTED), (value, True, NAVY)],
                 size=10.5, space_after=6, first=(i == 0))
        del p

    # The differentiator is that it already runs, so make it scannable from the room.
    card(slide, 0.42, 5.52, 6.6, 1.22, fill=GOODBG, edge=GOOD_EDGE, radius=0.09)
    qr = ROOT / "qr_live.png"
    if qr.exists():
        slide.shapes.add_picture(str(qr), Inches(0.58), Inches(5.66), Inches(0.94),
                                 Inches(0.94))
    tf = textbox(slide, 1.66, 5.68, 5.2, 0.92)
    rich(tf, [("LIVE WORKING PROTOTYPE   ", True, GREEN),
              ("·  scan it", False, MUTED)],
         size=8.6, space_after=2, first=True)
    para(tf, LIVE, size=13, bold=True, color=NAVY, space_after=2)
    para(tf, "Real ML-KEM-768 / ML-DSA-65 computed server-side. Evaluation and attack "
             "results: " + RESULTS, size=7.2, color=MUTED, space_after=0)

    # Keep the members clear of the brain graphic (x 7.5-11.0), so the left column.
    tf = textbox(slide, 0.42, 6.88, 6.6, 0.5)
    para(tf, "TEAM MEMBERS", size=7.4, bold=True, color=MUTED, space_after=2.5, first=True)
    para(tf, "  ·  ".join(MEMBERS), size=8.2, color=INK, space_after=0)


def slide2(slide):
    """Proposed solution."""
    drop(find(slide, "TextBox 8"))
    # The title placeholder is centred across 0.2-12.2 while the SIH logo starts at
    # x=10.7, so a long title runs under it. Shortened and sized down to stay clear.
    set_title(slide, "PQFW — A LEAK THAT NAMES ITSELF", size=25)

    section(slide, LEFT, TOP, 7.9, "Proposed Solution (Describe your Idea/Solution/Prototype)")

    # -- the mechanism, drawn -------------------------------------------------
    card(slide, LEFT, TOP + 0.34, 7.9, 1.72, radius=0.05)
    tf = textbox(slide, LEFT + 0.14, TOP + 0.42, 7.62, 0.26)
    para(tf, "Detailed explanation of the proposed solution", size=9.6, bold=True,
         color=NAVY, space_after=0, first=True)

    y = TOP + 0.76
    flowbox(slide, LEFT + 0.14, y, 1.72, 1.14, "Split the document",
            ["base body +", "m invisible", "mark slots"])
    arrow(slide, LEFT + 1.92, y + 0.57)
    flowbox(slide, LEFT + 2.20, y, 1.98, 1.14, "Two renderings, two keys",
            ["each slot written", "2 ways that look", "identical — encrypted", "under different keys"],
            fill=WARM, edge=WARM_EDGE, title_color=ORANGE)
    arrow(slide, LEFT + 4.24, y + 0.57)
    flowbox(slide, LEFT + 4.52, y, 1.62, 1.14, "One ciphertext",
            ["broadcast to all N", "— byte-identical", "for everybody"])
    arrow(slide, LEFT + 6.20, y + 0.57)
    flowbox(slide, LEFT + 6.48, y, 1.42, 1.14, "One key each",
            ["recipient holds", "1 of the 2 keys", "per slot"],
            fill=GOODBG, edge=GOOD_EDGE, title_color=GREEN)

    tf = textbox(slide, LEFT, TOP + 2.16, 7.9, 0.46)
    rich(tf, [("So the fingerprint is not something their software chose to add — it is a "
               "consequence of ", False, INK),
              ("which keys they hold", True, NAVY),
              (". The other rendering is an AES-GCM tag failure for them, and ", False, INK),
              ("no unmarked copy exists anywhere", True, NAVY),
              (" — not in the package, not in transit, not on the sender's disk.", False, INK)],
         size=9.6, space_after=0, first=True)

    # -- how it addresses the problem ----------------------------------------
    section(slide, LEFT, TOP + 2.72, 7.9, "How it addresses the problem")
    tf = textbox(slide, LEFT, TOP + 3.06, 7.9, 1.5)
    bullets(tf, [
        "Today every recipient who could decrypt is an equally plausible suspect — the "
        "decrypted bytes are identical for all of them.",
        "PQFW makes each copy forensically distinct while visually identical, so a leaked "
        "file resolves to one recipient and one decryption session.",
        "Server-side access logs can be edited by an administrator; a static watermark is "
        "the same for everyone. Both are replaced, not patched.",
    ], size=9.6, gap=4)

    # -- innovation -----------------------------------------------------------
    section(slide, 8.55, TOP, 4.36, "Innovation and uniqueness of the solution")
    cards = [
        ("Enforced by keys, not software",
         "Patching the client does not help. There is no code path around a tag check."),
        ("A provable error bound",
         "Chernoff bound from the code's own biases — not a Gaussian p-value, which we "
         "measured as anti-conservative."),
        ("It refuses to guess",
         "When evidence is thin the verdict is NO IDENTIFICATION — never the wrong person."),
        ("Session-level attribution",
         "Two opens by one person give two different fingerprints and two ledger records."),
    ]
    cy = TOP + 0.34
    for title, body in cards:
        card(slide, 8.55, cy, 4.36, 0.86, radius=0.07)
        tf = textbox(slide, 8.68, cy + 0.10, 4.1, 0.68)
        para(tf, title, size=9.4, bold=True, color=NAVY, space_after=2, first=True)
        para(tf, body, size=8.2, color=MUTED, space_after=0)
        cy += 0.96

    card(slide, 8.55, cy + 0.06, 4.36, 0.74, fill=GOODBG, edge=GOOD_EDGE, radius=0.07)
    tf = textbox(slide, 8.68, cy + 0.17, 4.1, 0.56)
    para(tf, "NOT A CONCEPT — IT IS RUNNING", size=7.6, bold=True, color=GREEN,
         space_after=2.5, first=True)
    para(tf, LIVE + "   ·   163 automated tests", size=9.6, bold=True, color=NAVY,
         space_after=0)

    # -- the output itself, reproduced as the system prints it --------------------
    # A verdict is the deliverable, so show one rather than describe it. Drawn natively
    # instead of screenshotted: the demo's UI is dark, and a dark screenshot prints
    # muddy and unreadable at slide size.
    ey = TOP + 3.94
    section(slide, LEFT, ey, 7.9, "What the system actually returns")
    card(slide, LEFT, ey + 0.30, 7.9, 1.26, fill=GOODBG, edge=GOOD_EDGE, radius=0.06)

    tf = textbox(slide, LEFT + 0.20, ey + 0.41, 4.5, 0.5)
    rich(tf, [("IDENTIFIED", True, GREEN), ("   r07, session #0", True, NAVY)],
         size=13, space_after=2, first=True)
    para(tf, "false-accusation probability at most 2.8 × 10⁻⁵⁹", size=8.6, color=MUTED,
         space_after=0)

    tf = textbox(slide, LEFT + 0.20, ey + 0.99, 4.5, 0.30)
    para(tf, "2 KB memo · 20 recipients · 301 mark slots · next suspect 10σ behind",
         size=7.8, color=MUTED, space_after=0)

    checks = [
        "statistical significance (provable bound < α)",
        "the accused's own ML-DSA-65 receipt verifies",
        "ledger hash chain intact",
        "block committed by 2 of 3 validators",
        "Merkle inclusion proof to the signed root",
    ]
    tf = textbox(slide, LEFT + 4.92, ey + 0.40, 3.3, 1.12)
    for i, check in enumerate(checks):
        rich(tf, [("✓  ", True, GREEN), (check, False, INK)], size=7.8, space_after=2.2,
             first=(i == 0))


def slide3(slide):
    """Technical approach. The diagram is the slide."""
    drop(find(slide, "TextBox 8"))
    set_title(slide, "TECHNICAL APPROACH")

    dw = 8.62  # diagram column width
    section(slide, LEFT, TOP, dw, "End-to-end flow",
            "distribute · decrypt & record · trace — every stage runs offline")

    bw, bh, gap = 1.92, 0.86, 0.30
    xs = [LEFT + i * (bw + gap) for i in range(4)]

    # -- row 1: distribute ----------------------------------------------------
    y1 = TOP + 0.50
    tf = textbox(slide, LEFT, y1 - 0.20, dw, 0.18)
    para(tf, "1  DISTRIBUTE", size=7.4, bold=True, color=ORANGE, space_after=0, first=True)
    flowbox(slide, xs[0], y1, bw, bh, "Sender's document",
            ["split into base +", "m mark slots"])
    arrow(slide, xs[0] + bw + 0.04, y1 + bh / 2)
    flowbox(slide, xs[1], y1, bw, bh, "Variant encryption",
            ["AES-256-GCM,", "a different key per rendering"],
            fill=WARM, edge=WARM_EDGE, title_color=ORANGE)
    arrow(slide, xs[1] + bw + 0.04, y1 + bh / 2)
    flowbox(slide, xs[2], y1, bw, bh, "Key bundles",
            ["wrapped with ML-KEM-768", "one key per slot each"])
    arrow(slide, xs[2] + bw + 0.04, y1 + bh / 2)
    flowbox(slide, xs[3], y1, bw, bh, "One package",
            ["identical ciphertext", "for all N recipients"])

    down_arrow(slide, LEFT + dw / 2, y1 + bh + 0.04, h=0.22)

    # -- row 2: decrypt and record -------------------------------------------
    # Every row reads left to right. An earlier draft ran this one right to left to
    # snake the flow, and the arrows still pointed right -- which said the opposite of
    # what the boxes did. Stages stack downwards instead.
    y2 = y1 + bh + 0.44
    tf = textbox(slide, LEFT, y2 - 0.20, dw, 0.18)
    para(tf, "2  DECRYPT  &  RECORD", size=7.4, bold=True, color=GREEN, space_after=0,
         first=True)
    flowbox(slide, xs[0], y2, bw, bh, "Recipient decrypts",
            ["unwraps bundle,", "spends one session"], fill=GOODBG, edge=GOOD_EDGE,
            title_color=GREEN)
    arrow(slide, xs[0] + bw + 0.04, y2 + bh / 2)
    flowbox(slide, xs[1], y2, bw, bh, "Uniquely marked copy",
            ["one rendering per slot;", "the other is a tag failure"],
            fill=GOODBG, edge=GOOD_EDGE, title_color=GREEN)
    arrow(slide, xs[1] + bw + 0.04, y2 + bh / 2)
    flowbox(slide, xs[2], y2, bw, bh, "Signed receipt",
            ["ML-DSA-65, recipient's", "own private key"],
            fill=GOODBG, edge=GOOD_EDGE, title_color=GREEN)
    arrow(slide, xs[2] + bw + 0.04, y2 + bh / 2)
    flowbox(slide, xs[3], y2, bw, bh, "Distributed ledger",
            ["3 validator replicas,", "2-of-3 block commit"],
            fill=GOODBG, edge=GOOD_EDGE, title_color=GREEN)

    down_arrow(slide, LEFT + dw / 2, y2 + bh + 0.04, h=0.22)

    # -- row 3: trace ---------------------------------------------------------
    y3 = y2 + bh + 0.44
    tf = textbox(slide, LEFT, y3 - 0.20, dw, 0.18)
    para(tf, "3  TRACE A LEAK", size=7.4, bold=True, color=RED, space_after=0, first=True)
    flowbox(slide, xs[0], y3, bw, bh, "Leaked copy",
            ["extract the slot bits"])
    arrow(slide, xs[0] + bw + 0.04, y3 + bh / 2)
    flowbox(slide, xs[1], y3, bw, bh, "Tardos scoring",
            ["score against every", "issued codeword"])
    arrow(slide, xs[1] + bw + 0.04, y3 + bh / 2)
    flowbox(slide, xs[2], y3, bw, bh, "Ledger lookup",
            ["commitment → receipt,", "signature + quorum checked"])
    arrow(slide, xs[2] + bw + 0.04, y3 + bh / 2)
    flowbox(slide, xs[3], y3, bw, bh, "Verifiable verdict",
            ["recipient + session", "+ provable error bound"],
            fill=WARM, edge=WARM_EDGE, title_color=ORANGE)

    tf = textbox(slide, LEFT, y3 + bh + 0.10, dw, 0.24)
    rich(tf, [("Offline and air-gapped throughout · ", True, NAVY),
              ("no cloud KMS, no public blockchain, no network call at any stage — "
               "asserted by a test that refuses every socket operation.", False, MUTED)],
         size=8.2, space_after=0, first=True)

    # -- right column ---------------------------------------------------------
    rx, rw = 9.30, 3.61
    section(slide, rx, TOP, rw, "Technologies to be used")
    tf = textbox(slide, rx, TOP + 0.32, rw, 1.72)
    for label, value in [
        ("Key exchange", "ML-KEM-768  (FIPS 203)"),
        ("Signatures", "ML-DSA-65  (FIPS 204)"),
        ("PQC library", "liboqs 0.16.0 via liboqs-python"),
        ("Content", "AES-256-GCM · HKDF-SHA3-256"),
        ("Fingerprint", "symmetric Tardos code (Škorić)"),
        ("Ledger", "hash chain + Merkle blocks, 2-of-3"),
        ("Carriers", "zero-width space · PDF kerning"),
        ("Stack", "Python 3.11 · FastAPI · NumPy · Docker"),
    ]:
        rich(tf, [(label + "   ", True, NAVY), (value, False, INK)], size=8.4,
             space_after=2.6, first=(label == "Key exchange"))

    section(slide, rx, TOP + 2.34, rw, "Methodology and process for implementation")
    tf = textbox(slide, rx, TOP + 2.66, rw, 1.5)
    bullets(tf, [
        "Safety and audit layers built and tested before any tracing existed.",
        "Test-first throughout: 163 tests, including the central claim that a recipient "
        "cannot decrypt the other variant.",
        "Every attack on the carrier measured and published — including the four that "
        "defeat it.",
    ], size=8.4, gap=3.4)

    card(slide, rx, TOP + 4.10, rw, 1.02, fill=GOODBG, edge=GOOD_EDGE, radius=0.07)
    tf = textbox(slide, rx + 0.14, TOP + 4.20, rw - 0.28, 0.84)
    para(tf, "WHY THIS DESIGN", size=7.6, bold=True, color=GREEN, space_after=3, first=True)
    para(tf, "Broadcast ciphertext is shared by everyone; only a ~14 KB key bundle differs "
             "per recipient, independent of document size and of N.", size=8.2, color=MUTED,
         space_after=0)


def slide4(slide):
    """Feasibility and viability."""
    drop(find(slide, "TextBox 8"))
    set_title(slide, "FEASIBILITY AND VIABILITY")

    colw, gap = 4.02, 0.23
    xs = [LEFT, LEFT + colw + gap, LEFT + 2 * (colw + gap)]

    section(slide, xs[0], TOP, colw, "Analysis of the feasibility of the idea")
    card(slide, xs[0], TOP + 0.36, colw, 2.18, radius=0.06)
    tf = textbox(slide, xs[0] + 0.15, TOP + 0.48, colw - 0.3, 2.4)
    items = [
        ("Already built and running.", "Not a concept — a working deployment anyone can "
                                       "open right now."),
        ("Runs on commodity CPU.", "No GPU, no HSM. The whole demo fits a free 0.1-vCPU tier."),
        ("Zero licensing cost.", "Open-source primitives end to end; NIST-standardised, not "
                                 "bespoke."),
        ("Deploys air-gapped.", "No cloud KMS, no public chain, no outbound call at any stage."),
        ("Drops in beside existing flows.", "The sender already encrypts once for many; this "
                                            "replaces that step, not the whole system."),
    ]
    for i, (head, body) in enumerate(items):
        rich(tf, [(head + " ", True, NAVY), (body, False, MUTED)], size=8.8,
             space_after=6, first=(i == 0))

    section(slide, xs[1], TOP, colw, "Potential challenges and risks")
    card(slide, xs[1], TOP + 0.36, colw, 2.18, fill=WARM, edge=WARM_EDGE, radius=0.06)
    tf = textbox(slide, xs[1] + 0.15, TOP + 0.48, colw - 0.3, 2.4)
    risks = [
        ("Carrier fragility.", "Retyping, OCR or stripping invisible characters destroys "
                               "a text watermark."),
        ("Word insertion desynchronises.", "Slot addresses are ordinal, so adding a word "
                                           "shifts every later slot."),
        ("Short documents, weaker codes.", "A memo holds ~300 slots; the Tardos bound asks "
                                           "for far more."),
        ("Unframeability.", "The sender knows every codeword, so this proves traceability, "
                            "not non-framing."),
        ("Collusion.", "Several recipients can compare copies and splice them together."),
    ]
    for i, (head, body) in enumerate(risks):
        rich(tf, [(head + " ", True, AMBER), (body, False, MUTED)], size=8.8,
             space_after=6, first=(i == 0))

    section(slide, xs[2], TOP, colw, "Strategies for overcoming these challenges")
    card(slide, xs[2], TOP + 0.36, colw, 2.18, fill=GOODBG, edge=GOOD_EDGE, radius=0.06)
    tf = textbox(slide, xs[2] + 0.15, TOP + 0.48, colw - 0.3, 2.4)
    fixes = [
        ("Publish the attacks that win.", "Every one is measured with its bit error rate, "
                                          "beside the ones survived."),
        ("Fail safe, not loud.", "When an attack wins the result is a failure to identify "
                                 "— misidentification stayed at 0.0% across a 0–95% "
                                 "erasure sweep."),
        ("Report the reachable bound.", "protect states the best error probability the "
                                        "document can support before anything is sent."),
        ("Tardos codes for collusion.", "Where colluders agree they are stuck — no one "
                                        "holds the other key."),
        ("Content-anchored slots.", "The named next step, replacing ordinal addressing."),
    ]
    for i, (head, body) in enumerate(fixes):
        rich(tf, [(head + " ", True, GREEN), (body, False, MUTED)], size=8.8,
             space_after=6, first=(i == 0))

    # -- measured evidence strip ---------------------------------------------
    card(slide, LEFT, TOP + 2.70, RIGHT - LEFT, 1.26, radius=0.05)
    tf = textbox(slide, LEFT + 0.18, TOP + 2.80, 3.3, 0.28)
    para(tf, "MEASURED, NOT ASSERTED", size=8.4, bold=True, color=NAVY, space_after=0,
         first=True)

    figures = [
        ("100%", "coalition of 8 traced\nat the prescribed code length", GREEN),
        ("0.0%", "misidentification across\na 0–95% erasure sweep", GREEN),
        ("2.8e-59", "provable false-accusation\nbound on the live demo", NAVY),
        ("0 / 10,000", "innocent trials accused\nat α ≤ 1e-5", GREEN),
        ("4", "attacks that defeat the\ncarrier — all published", RED),
        ("163", "automated tests,\nall passing", NAVY),
    ]
    sw = (RIGHT - LEFT - 0.36) / len(figures)
    for i, (value, label, color) in enumerate(figures):
        stat(slide, LEFT + 0.18 + i * sw, TOP + 3.12, sw, value, label, color=color, vsize=17)

    # -- deployment roadmap ---------------------------------------------------
    # Judges reward a realistic path to deployment over an ambitious one, so this is
    # the actual next four steps rather than an aspiration.
    section(slide, LEFT, TOP + 4.14, RIGHT - LEFT, "Path to deployment")
    steps = [
        ("NOW", "Working prototype", "text and PDF carriers, 3-validator ledger, live"),
        ("NEXT", "Content-anchored slots", "removes the word-insertion weakness"),
        ("THEN", "Departmental pilot", "validators held by three separate offices"),
        ("SCALE", "Cross-ministry", "one validator per participating ministry"),
    ]
    sx = LEFT
    stepw = (RIGHT - LEFT - 3 * 0.30) / 4
    for i, (tag, head, body) in enumerate(steps):
        tint = GOODBG if i == 0 else CARD
        edge = GOOD_EDGE if i == 0 else CARD_EDGE
        card(slide, sx, TOP + 4.50, stepw, 0.88, fill=tint, edge=edge, radius=0.07)
        tf = textbox(slide, sx + 0.14, TOP + 4.60, stepw - 0.28, 0.7)
        para(tf, tag, size=7, bold=True, color=GREEN if i == 0 else MUTED,
             space_after=1.5, first=True)
        para(tf, head, size=9.4, bold=True, color=NAVY, space_after=1.5)
        para(tf, body, size=7.8, color=MUTED, space_after=0)
        if i < 3:
            arrow(slide, sx + stepw + 0.04, TOP + 4.94, w=0.22)
        sx += stepw + 0.30


def slide5(slide):
    """Impact and benefits."""
    drop(find(slide, "TextBox 8"))
    set_title(slide, "IMPACT AND BENEFITS")

    colw = 6.20
    x2 = LEFT + colw + 0.31

    section(slide, LEFT, TOP, colw, "Potential impact on the target audience")
    card(slide, LEFT, TOP + 0.36, colw, 1.86, radius=0.06)
    tf = textbox(slide, LEFT + 0.16, TOP + 0.48, colw - 0.32, 1.7)
    for i, (head, body) in enumerate([
        ("Service headquarters.", "Operational orders and classified assessments "
                                  "distributed to a named list become individually "
                                  "accountable, not collectively deniable."),
        ("Defence procurement.", "Tender documents and technical specifications reach "
                                 "vendors traceably; a pre-bid leak has an owner."),
        ("DRDO and defence PSUs.", "Design data shared with partners and contractors "
                                   "carries a non-repudiable receipt per recipient."),
        ("Inter-agency sharing.", "Intelligence circulated across agencies keeps its "
                                  "provenance without a central authority anyone must "
                                  "trust."),
    ]):
        rich(tf, [(head + " ", True, NAVY), (body, False, MUTED)], size=9.2,
             space_after=6, first=(i == 0))

    section(slide, x2, TOP, colw, "Benefits of the solution (social, economic, environmental)")
    card(slide, x2, TOP + 0.36, colw, 1.86, fill=GOODBG, edge=GOOD_EDGE, radius=0.06)
    tf = textbox(slide, x2 + 0.16, TOP + 0.48, colw - 0.32, 1.7)
    for i, (head, body) in enumerate([
        ("Deterrence is the real product.", "When every holder knows their copy is "
                                            "individually accountable, most leaks never "
                                            "happen."),
        ("Protects the accused too.", "A stated error probability and a refusal to guess "
                                      "are what stop an innocent official being named."),
        ("Zero licensing cost.", "Open-source and free-tier; per-department rollout cost is "
                                 "effectively nil."),
        ("Quantum-durable.", "A defence assessment stays sensitive for decades; FIPS 203/204 "
                             "resist harvest-now-decrypt-later."),
        ("Scales unchanged.", "Any organisation distributing one document to a named "
                              "list — the architecture does not change, only the list."),
    ]):
        rich(tf, [(head + " ", True, GREEN), (body, False, MUTED)], size=9.2,
             space_after=6, first=(i == 0))

    # -- before / after -------------------------------------------------------
    section(slide, LEFT, TOP + 2.36, RIGHT - LEFT, "What changes")
    y = TOP + 2.68
    card(slide, LEFT, y, colw, 1.36, fill=RGBColor(0xFA, 0xEE, 0xEE),
         edge=RGBColor(0xE4, 0xC2, 0xC2), radius=0.06)
    tf = textbox(slide, LEFT + 0.18, y + 0.13, colw - 0.36, 1.1)
    para(tf, "TODAY", size=8.4, bold=True, color=RED, space_after=4, first=True)
    bullets(tf, [
        "Every cleared recipient is an equally plausible suspect.",
        "Access logs can be edited by the administrator who holds them.",
        "One identical watermark for all recipients attributes nothing.",
    ], size=8.8, gap=3, color=MUTED)

    card(slide, x2, y, colw, 1.36, fill=GOODBG, edge=GOOD_EDGE, radius=0.06)
    tf = textbox(slide, x2 + 0.18, y + 0.13, colw - 0.36, 1.1)
    para(tf, "WITH PQFW", size=8.4, bold=True, color=GREEN, space_after=4, first=True)
    bullets(tf, [
        "A leaked copy names one recipient and one decryption session.",
        "Records are replicated 3 ways; one compromised admin is out-voted.",
        "Every copy is distinct, and the accusation carries a provable bound.",
    ], size=8.8, gap=3, color=MUTED)

    # -- what it costs to run, which is the other half of impact ------------------
    section(slide, LEFT, y + 1.44, RIGHT - LEFT, "Cost of running it")
    card(slide, LEFT, y + 1.76, RIGHT - LEFT, 0.98, radius=0.05)
    numbers = [
        ("116 KB", "shared ciphertext —\nthe same bytes for everyone", NAVY),
        ("34 KB", "per recipient, and\nindependent of N", NAVY),
        ("0", "GPUs, HSMs and\ncloud services required", GREEN),
        ("₹0", "licensing cost —\nopen-source throughout", GREEN),
        ("< 1 s", "to trace a leak against\n1,000 recipients", NAVY),
    ]
    nw = (RIGHT - LEFT - 0.36) / len(numbers)
    for i, (value, label, color) in enumerate(numbers):
        stat(slide, LEFT + 0.18 + i * nw, y + 1.86, nw, value, label, color=color, vsize=16)


def slide6(slide):
    """Research and references."""
    drop(find(slide, "TextBox 8"))
    set_title(slide, "RESEARCH AND REFERENCES")

    colw = 4.02
    gap = 0.23
    xs = [LEFT, LEFT + colw + gap, LEFT + 2 * (colw + gap)]

    section(slide, xs[0], TOP, colw, "Standards and specifications")
    tf = textbox(slide, xs[0], TOP + 0.34, colw, 2.4)
    for i, (head, body) in enumerate([
        ("FIPS 203 (2024)", "Module-Lattice-Based Key-Encapsulation Mechanism — ML-KEM. NIST."),
        ("FIPS 204 (2024)", "Module-Lattice-Based Digital Signature Standard — ML-DSA. NIST."),
        ("FIPS 202", "SHA-3 permutation-based hash and extendable-output functions."),
        ("NIST SP 800-38D", "Galois/Counter Mode for AES, used for every ciphertext here."),
    ]):
        rich(tf, [(head + "  ", True, NAVY), (body, False, MUTED)], size=8.6,
             space_after=6, first=(i == 0))

    section(slide, xs[1], TOP, colw, "Methods and literature")
    tf = textbox(slide, xs[1], TOP + 0.34, colw, 2.4)
    for i, (head, body) in enumerate([
        ("Tardos (2003)", "Optimal probabilistic fingerprint codes. STOC."),
        ("Škorić et al. (2008)", "Symmetric Tardos fingerprinting codes for arbitrary "
                                            "alphabet sizes. Designs, Codes and Cryptography."),
        ("Boneh & Shaw (1998)", "Collusion-secure fingerprinting for digital data. "
                                "IEEE Trans. Information Theory."),
        ("Open Quantum Safe", "liboqs — the C library providing both mechanisms used here."),
        ("Brakerski–Fan–Vercauteren", "Somewhat-homomorphic encryption; the route to "
                                                 "post-quantum asymmetric fingerprinting. Future work."),
    ]):
        rich(tf, [(head + "  ", True, NAVY), (body, False, MUTED)], size=8.6,
             space_after=5.5, first=(i == 0))

    section(slide, xs[2], TOP, colw, "Our work — live and inspectable")
    card(slide, xs[2], TOP + 0.34, colw, 1.16, fill=GOODBG, edge=GOOD_EDGE, radius=0.07)
    tf = textbox(slide, xs[2] + 0.15, TOP + 0.45, colw - 0.3, 0.96)
    para(tf, "WORKING PROTOTYPE", size=7.6, bold=True, color=GREEN, space_after=3, first=True)
    para(tf, LIVE, size=10.5, bold=True, color=NAVY, space_after=3)
    para(tf, "Five guided steps, real post-quantum cryptography computed server-side.",
         size=8, color=MUTED, space_after=0)

    card(slide, xs[2], TOP + 1.62, colw, 1.12, radius=0.07)
    tf = textbox(slide, xs[2] + 0.15, TOP + 1.72, colw - 0.3, 0.92)
    para(tf, "EVALUATION AND ATTACK RESULTS", size=7.6, bold=True, color=NAVY,
         space_after=3, first=True)
    para(tf, RESULTS, size=7.6, bold=True, color=NAVY, space_after=3)
    para(tf, "Every figure produced by executing the library, with the commit recorded.",
         size=8, color=MUTED, space_after=0)

    # -- what we verified -----------------------------------------------------
    section(slide, LEFT, TOP + 2.90, RIGHT - LEFT,
            "Every requirement in " + PS_ID + ", and where it is met",
            "each one is exercised by an automated test, and by a step of the live demo")
    card(slide, LEFT, TOP + 3.32, RIGHT - LEFT, 1.62, radius=0.05)

    reqs = [
        ("Unique invisible forensic watermark at the moment of decryption", True),
        ("Specific to each recipient and each decryption session", True),
        ("Every copy visually identical, forensically distinct", True),
        ("Each decryption cryptographically bound to the recipient's identity", True),
        ("Signature generated with the recipient's own private key", True),
        ("NIST-standardised PQC for key exchange and digital signatures", True),
        ("Immutable audit layer implemented as a distributed ledger", True),
        ("No single administrator or compromised account can alter records", True),
        ("Extract the watermark, match it against the ledger, verify it", True),
        ("Complete operation offline and air-gapped", True),
        ("No dependency on external cloud KMS services", True),
        ("No dependency on public blockchain networks", True),
    ]
    cw = (RIGHT - LEFT - 0.4) / 2
    for i, (text, ok) in enumerate(reqs):
        col, row = divmod(i, 6)
        tf = textbox(slide, LEFT + 0.2 + col * cw, TOP + 3.42 + row * 0.245, cw - 0.1, 0.24)
        rich(tf, [("✓  ", True, GREEN), (text, False, INK)], size=8.3, space_after=0,
             first=True)


# ---------------------------------------------------------------------------


def main() -> None:
    prs = Presentation(TEMPLATE)

    # the template's own instructions say to delete the pointers slide before upload
    xml_slides = prs.slides._sldIdLst
    slides = list(xml_slides)
    prs.part.drop_rel(slides[6].rId)
    xml_slides.remove(slides[6])

    builders = [slide1, slide2, slide3, slide4, slide5, slide6]
    for index, build in enumerate(builders):
        slide = prs.slides[index]
        if index > 0:
            set_team_oval(slide)
        build(slide)
        note = NOTES.get(index + 1)
        if note:
            slide.notes_slide.notes_text_frame.text = note

    OUT.parent.mkdir(parents=True, exist_ok=True)
    prs.save(OUT)
    print(f"wrote {OUT}  ({OUT.stat().st_size:,} bytes, {len(prs.slides.__iter__.__self__._sldIdLst)} slides)")


if __name__ == "__main__":
    main()
