"""pqfw -- five commands: enroll, protect, open, trace, audit.

This is what the live demo is driven from, so the output is written to be read out
loud rather than parsed. ``--json`` is there for the web front end and for scripts.

    pqfw enroll  --recipients 20 --out ./state
    pqfw protect --doc report.txt --state ./state --coalition 3 --eps 1e-6
    pqfw open    --doc-id report --recipient r07 --state ./state --out leaked.txt
    pqfw trace   --doc-id report --leaked leaked.txt --state ./state
    pqfw audit   --state ./state [--tamper 2]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import numpy as np

from pqfw import ledger as L
from pqfw import workflow
from pqfw.store import Store

# ---------------------------------------------------------------------------
# presentation
# ---------------------------------------------------------------------------

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def green(t: str) -> str:
    return _c(t, "32")


def red(t: str) -> str:
    return _c(t, "31")


def yellow(t: str) -> str:
    return _c(t, "33")


def bold(t: str) -> str:
    return _c(t, "1")


def dim(t: str) -> str:
    return _c(t, "2")


def _safe(sym: str, fallback: str) -> str:
    """Windows consoles in a legacy code page cannot print a tick."""
    try:
        sym.encode(sys.stdout.encoding or "utf-8")
        return sym
    except (UnicodeEncodeError, LookupError):
        return fallback


TICK = _safe("✓", "OK")
CROSS = _safe("✗", "X")
ARROW = _safe("→", "->")


def mark(ok: bool) -> str:
    return green(TICK) if ok else red(CROSS)


def rule(title: str = "") -> None:
    line = "-" * 64
    print(dim(line if not title else f"-- {title} " + "-" * max(0, 60 - len(title))))


def field(label: str, value: Any, width: int = 22) -> None:
    print(f"  {label.ljust(width)} {value}")


def emit(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, default=str))


def fmt_p(p: float, log10_p: float) -> str:
    """A p-value that has underflowed is reported in log space, not as zero."""
    if p == 0.0:
        return f"< 1e-300  (log10 p = {log10_p:.1f})"
    if p < 1e-4:
        return f"{p:.3e}"
    return f"{p:.6f}"


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_enroll(args: argparse.Namespace) -> int:
    store = Store(args.state)
    info = workflow.enroll(
        store,
        recipients=args.recipients,
        witnesses=args.witnesses,
        threshold=args.threshold,
    )
    if args.json:
        emit(info, True)
        return 0

    rule("enroll")
    field("state", store.root)
    field("recipients", f"{len(info['recipients'])}  ({info['recipients'][0]} .. {info['recipients'][-1]})")
    field("witnesses", f"{len(info['witnesses'])}, {info['threshold']}-of-{len(info['witnesses'])} required")
    print()
    alg = info["algorithms"]
    field("key encapsulation", f"{alg['kem']}   (FIPS 203)")
    field("signatures", f"{alg['sig']}   (FIPS 204)")
    field("content encryption", alg["aead"])
    field("hash / KDF", f"{alg['hash']} / {alg['kdf']}")
    field("liboqs", alg["liboqs"])
    print()
    print(dim(f"  recipient devices  {store.root / 'recipients'}"))
    print(dim(f"  witness keys       {store.root / 'witnesses'}"))
    print(dim(f"  sealed store       {store.sealed_path}"))
    return 0


def cmd_protect(args: argparse.Namespace) -> int:
    store = Store.open(args.state)
    source = Path(args.doc).read_bytes()
    doc_id = args.doc_id or Path(args.doc).stem
    rng = np.random.default_rng(args.seed) if args.seed is not None else np.random.default_rng()

    result = workflow.protect(
        store,
        source,
        doc_id=doc_id,
        carrier_name=args.carrier,
        coalition=args.coalition,
        eps1=args.eps,
        constant=args.constant,
        slots=args.slots,
        rng=rng,
    )
    if args.json:
        emit(result.to_json(), True)
        return 0

    rule("protect")
    field("document", f"{args.doc}  ({len(source)} bytes)")
    field("doc id", result.doc_id)
    field("carrier", args.carrier)
    field("recipients", result.recipients)
    field("mark slots", f"{result.m}")
    if result.capped:
        print(
            yellow(
                f"  {'code length'.ljust(22)} capped by the carrier: "
                f"{result.m_requested} slots wanted for c={args.coalition}, eps={args.eps:g}, "
                f"{result.capacity} available"
            )
        )
        print(
            dim(
                "                         a shorter code gives weaker evidence, not false\n"
                "                         evidence: the p-value is computed from the score\n"
                "                         actually observed"
            )
        )
    reachable = result.achievable_eps
    line = f"{reachable:.2e} against a single leaker"
    if reachable >= args.eps:
        print(yellow(f"  {'best achievable eps'.ljust(22)} {line}  (you asked for {args.eps:g})"))
        print(
            dim(
                "                         this document does not hold enough slots to reach the\n"
                "                         requested confidence. Use a longer document, or accept\n"
                "                         the weaker bound -- it is reported, not hidden."
            )
        )
    else:
        field("best achievable eps", line)
    print()
    size = result.size
    field("public ciphertext", f"{size['public_bytes']:,} bytes  (identical for everyone)")
    field("per recipient", f"{size['per_recipient_bytes']:,} bytes  (ML-KEM ct + wrapped bundle)")
    field("total", f"{size['total_bytes']:,} bytes")
    print()
    print(dim(f"  package  {result.package_path}"))
    print(
        dim(
            "  every recipient receives the same ciphertext; only the wrapped key bundle\n"
            "  differs, and it decides which rendering of each slot they can decrypt"
        )
    )
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    store = Store.open(args.state)
    result = workflow.open_as(store, args.doc_id, args.recipient)
    out = Path(args.out) if args.out else Path(f"{args.recipient}-{args.doc_id}.out")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(result.document)

    if args.json:
        emit(
            {
                "doc_id": result.doc_id,
                "recipient_id": result.recipient_id,
                "doc_hash": result.doc_hash,
                "ledger_seq": result.ledger_seq,
                "entry_hash": result.entry_hash,
                "out": str(out),
                "bytes": len(result.document),
            },
            True,
        )
        return 0

    rule("open")
    field("recipient", args.recipient)
    field("doc id", args.doc_id)
    field("written to", f"{out}  ({len(result.document):,} bytes)")
    field("copy hash", result.doc_hash[:32] + dim("..."))
    print()
    field("receipt signed", f"ML-DSA-65 by {args.recipient}")
    field("ledger entry", f"seq {result.ledger_seq}   {result.entry_hash[:24]}" + dim("..."))
    print()
    print(
        dim(
            "  this copy carries a fingerprint that its holder could not decline: they\n"
            "  hold one variant key per slot and cannot decrypt the other rendering"
        )
    )
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    store = Store.open(args.state)
    leaked = Path(args.leaked).read_bytes()
    report = workflow.trace_leak(store, args.doc_id, leaked, alpha=args.alpha)

    if args.json:
        emit(report.to_json(), True)
        return 0 if report.conclusive else 1

    rule("trace")
    field("leaked file", f"{args.leaked}  ({len(leaked):,} bytes)")
    field("doc id", report.doc_id)
    field("readable slots", f"{report.m_eff} of {report.m}")
    field("alpha", f"{report.alpha:g}")
    print()

    if report.accused is None:
        print(red("  no recipients to score against this document"))
        return 1

    a = report.accused.accusation
    headline = f"{bold(report.accused.recipient_id)}"
    print(f"  {'best match'.ljust(22)} {headline}")
    field("z-score", f"{a.z_score:.2f} sigma")
    field("p-value", fmt_p(a.p_value, a.log10_p_value))
    field("raw score", f"{a.raw_score:.1f}")
    print()

    print("  " + dim("runners-up"))
    for suspect in report.runners_up:
        b = suspect.accusation
        print(
            f"    {suspect.recipient_id.ljust(8)} z={b.z_score:7.2f}   "
            f"p={fmt_p(b.p_value, b.log10_p_value)}"
        )
    print()

    print("  " + dim("corroboration"))
    print(f"    {mark(report.statistically_significant)} statistical significance (p < alpha)")
    print(f"    {mark(report.receipt_signature_valid)} recipient's ML-DSA-65 receipt verifies")
    print(f"    {mark(report.chain_ok)} ledger hash chain intact")
    print(
        f"    {mark(report.checkpoint_valid)} checkpoint witnesses "
        f"{report.checkpoint_witnesses}/{report.checkpoint_required} required"
    )
    print(f"    {mark(report.inclusion_proof_valid)} Merkle inclusion proof to the signed root")
    if report.ledger_seq is not None:
        print(f"      {dim('ledger entry')} seq {report.ledger_seq}")
    print()

    if report.conclusive:
        print(
            "  "
            + green(bold(f"IDENTIFIED  {ARROW}  {report.accused.recipient_id}"))
            + f"   false-accusation probability {fmt_p(a.p_value, a.log10_p_value)}"
        )
    elif report.statistically_significant:
        print("  " + yellow(bold("UNCORROBORATED")))
        print(
            dim(
                "  the marks match, but the ledger evidence does not stand up. This is a\n"
                "  lead, not an identification."
            )
        )
    else:
        print("  " + red(bold("NO IDENTIFICATION")))
        print(dim("  no recipient's codeword explains these marks at the requested confidence."))

    for note in report.notes:
        print(dim(f"    note: {note}"))
    return 0 if report.conclusive else 1


def cmd_audit(args: argparse.Namespace) -> int:
    store = Store.open(args.state)

    restored = workflow.restore(store) if args.restore else False

    tampered = None
    if args.tamper is not None:
        tampered = workflow.tamper(store, args.tamper, field=args.tamper_field)

    if args.checkpoint:
        workflow.checkpoint(store)

    info = workflow.audit(store)

    anchors: list[str] = []
    if not args.no_qr:
        ledger = store.ledger()
        for cp in ledger.checkpoints:
            path = store.root / "anchors" / f"checkpoint-{cp.index:03d}.png"
            L.export_checkpoint_qr(cp, path)
            anchors.append(str(path))
    info["anchors"] = anchors
    info["restored"] = restored
    if tampered:
        info["tampered"] = tampered

    if args.json:
        emit(info, True)
        return 0 if info["ok"] else 1

    rule("audit")
    if restored:
        print(green("  restored the pre-tamper ledger from its pristine copy"))
        print()
    if tampered:
        print(
            yellow(
                f"  deliberately corrupted ledger entry {tampered['seq']} "
                f"field {tampered['field']!r}"
            )
        )
        print(dim(f"    was  {tampered['before']}"))
        print(dim(f"    now  {tampered['after']}"))
        print()

    chain = info["chain"]
    field("entries", info["entries"])
    print(f"  {'hash chain'.ljust(22)} {mark(chain['ok'])} " + ("intact" if chain["ok"] else red("BROKEN")))
    if not chain["ok"]:
        field("first bad entry", red(f"seq {chain['first_bad_seq']}"))
        for problem in chain["problems"][:6]:
            print(red(f"      {problem}"))
    print()

    print("  " + dim(f"checkpoints ({info['witness_threshold']}-of-{info['witnesses_enrolled']} witnesses)"))
    if not info["checkpoints"]:
        print(dim("    none yet -- run with --checkpoint"))
    for cp in info["checkpoints"]:
        print(
            f"    {mark(cp['valid'])} #{cp['index']}  seq {cp['range'][0]}-{cp['range'][1]}  "
            f"{cp['witnesses']}/{info['witness_threshold']} witnesses  root {cp['root'][:16]}"
            + dim("...")
        )
        print(
            f"      {mark(cp['root_matches_entries'])} the signed root still covers exactly "
            f"these {cp['covers_expected']} entries"
        )
        if not cp["root_matches_entries"]:
            missing = cp["covers_expected"] - cp["covers_entries"]
            why = (
                f"{missing} of {cp['covers_expected']} witnessed entries are gone"
                if missing
                else "the entries are all present but their contents have changed"
            )
            print(red(f"        the ledger no longer reproduces this witnessed root: {why}"))
    if anchors:
        print()
        print(dim(f"  QR anchors written to {store.root / 'anchors'}"))
        print(
            dim(
                "  print one and the paper is a witness: a rewritten ledger cannot match\n"
                "  a root that was published before it was rewritten"
            )
        )
    print()
    alg = info["algorithms"]
    field("primitives", f"{alg['kem']} / {alg['sig']} / {alg['aead']} / {alg['hash']}")
    return 0 if chain["ok"] else 1


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqfw",
        description="Post-quantum forensic watermarking: encrypt once, fingerprint per "
        "recipient, trace a leak with a stated false-accusation probability.",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("enroll", help="create recipient keys and the witness set")
    p.add_argument("--recipients", type=int, default=20)
    p.add_argument("--witnesses", type=int, default=3)
    p.add_argument("--threshold", type=int, default=2)
    p.add_argument("--out", "--state", dest="state", default="./state")
    p.set_defaults(func=cmd_enroll)

    p = sub.add_parser("protect", help="encrypt a document once for every recipient")
    p.add_argument("--doc", required=True)
    p.add_argument("--doc-id", default=None)
    p.add_argument("--state", default="./state")
    p.add_argument("--carrier", default="text-zwsp")
    p.add_argument("--coalition", type=int, default=3, help="largest coalition to design for")
    p.add_argument("--eps", type=float, default=1e-6, help="target false-accusation probability")
    p.add_argument("--constant", type=float, default=100.0, help="Tardos code-length constant")
    p.add_argument("--slots", type=int, default=None, help="override the computed code length")
    p.add_argument("--seed", type=int, default=None, help="seed the RNG for a reproducible build")
    p.set_defaults(func=cmd_protect)

    p = sub.add_parser("open", help="decrypt as one recipient and sign a receipt")
    p.add_argument("--doc-id", required=True)
    p.add_argument("--recipient", required=True)
    p.add_argument("--state", default="./state")
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_open)

    p = sub.add_parser("trace", help="identify the source of a leaked copy")
    p.add_argument("--doc-id", required=True)
    p.add_argument("--leaked", required=True)
    p.add_argument("--state", default="./state")
    p.add_argument("--alpha", type=float, default=1e-6)
    p.set_defaults(func=cmd_trace)

    p = sub.add_parser("audit", help="verify the chain, the checkpoints, export QR anchors")
    p.add_argument("--state", default="./state")
    p.add_argument("--checkpoint", action="store_true", help="cut a new witness checkpoint first")
    p.add_argument("--tamper", type=int, default=None, metavar="SEQ",
                   help="deliberately corrupt an entry, to demonstrate detection")
    p.add_argument("--tamper-field", default="doc_hash")
    p.add_argument("--restore", action="store_true",
                   help="undo a previous --tamper, so the demo can be repeated")
    p.add_argument("--no-qr", action="store_true")
    p.set_defaults(func=cmd_audit)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (KeyError, ValueError, FileNotFoundError, IndexError) as exc:
        print(red(f"error: {exc}"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
