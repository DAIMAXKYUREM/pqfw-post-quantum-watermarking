"""Task 7: the five commands.

Driven through ``main()`` with ``--json`` so the assertions are about behaviour and
exit codes rather than about spacing. The human-readable path is exercised too, because
a demo driver that crashes while formatting is a demo that does not happen.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pqfw.cli import main

_PARAGRAPH = (
    "DISTRIBUTION NOTE. The attached assessment is released under the terms set out "
    "in the covering letter and is accountable to the individual named against each "
    "copy. Recipients may not reproduce, forward, extract from, or otherwise "
    "circulate this material to any person outside the distribution list without "
    "the written authority of the issuing office, whose decision on such requests "
    "is final and is not subject to any appeal process of any kind whatsoever.\n\n"
)

# Long enough that the code the carrier can hold clears 1e-6 comfortably rather than
# sitting on the threshold. A single leaker's expected z-score grows as sqrt(m), so a
# short memo lands near the boundary and the assertions would flap; the boundary itself
# is tested deliberately in test_a_short_document_cannot_reach_the_requested_eps.
SOURCE = _PARAGRAPH * 5


@pytest.fixture()
def workspace(tmp_path, capsys):
    doc = tmp_path / "note.txt"
    doc.write_text(SOURCE, encoding="utf-8")
    state = tmp_path / "state"

    assert main(["--json", "enroll", "--recipients", "12", "--out", str(state)]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "--json", "protect",
                "--doc", str(doc),
                "--state", str(state),
                "--coalition", "3",
                "--eps", "1e-6",
                "--seed", "7",
            ]
        )
        == 0
    )
    protect = json.loads(capsys.readouterr().out)
    return tmp_path, state, doc, protect


def _json(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------------------


def test_enroll_reports_the_post_quantum_primitives(tmp_path, capsys) -> None:
    assert main(["--json", "enroll", "--recipients", "4", "--out", str(tmp_path / "s")]) == 0
    info = _json(capsys)
    assert info["algorithms"]["kem"] == "ML-KEM-768"
    assert info["algorithms"]["sig"] == "ML-DSA-65"
    assert len(info["recipients"]) == 4
    assert info["threshold"] == 2 and len(info["witnesses"]) == 3


def test_protect_reports_the_cap_and_the_broadcast_size(workspace) -> None:
    _tmp, _state, _doc, protect = workspace
    assert protect["capped_by_carrier"] is True
    assert protect["slots"] == protect["carrier_capacity"] < protect["slots_requested"]
    assert protect["size"]["per_recipient_bytes"] < protect["size"]["public_bytes"]
    assert protect["achievable_eps"] < 1e-6, "this document holds enough slots"


def test_a_short_document_cannot_reach_the_requested_eps_and_says_so(
    tmp_path, capsys
) -> None:
    """The honest failure. A one-paragraph memo holds ~70 slots, which puts the best
    achievable false-accusation probability around 1e-6 -- right on the threshold that
    was requested. Reporting the reachable bound up front is what stops that becoming
    a surprise at trace time."""
    doc = tmp_path / "short.txt"
    doc.write_text(_PARAGRAPH, encoding="utf-8")
    state = tmp_path / "state"
    main(["--json", "enroll", "--recipients", "12", "--out", str(state)])
    capsys.readouterr()

    main(["--json", "protect", "--doc", str(doc), "--state", str(state),
          "--eps", "1e-9", "--seed", "3"])
    protect = json.loads(capsys.readouterr().out)
    assert protect["capped_by_carrier"] is True
    assert protect["achievable_eps"] > 1e-9, "the requested bound is out of reach"

    main(["protect", "--doc", str(doc), "--state", str(state), "--doc-id", "short2",
          "--eps", "1e-9", "--seed", "3"])
    out = capsys.readouterr().out
    assert "best achievable eps" in out
    assert "does not hold enough slots" in out


def test_open_then_trace_identifies_the_recipient(workspace, capsys) -> None:
    _tmp, state, _doc, _protect = workspace
    leaked = state.parent / "leaked.txt"

    assert (
        main(["--json", "open", "--doc-id", "note", "--recipient", "r05",
              "--state", str(state), "--out", str(leaked)])
        == 0
    )
    opened = _json(capsys)
    assert opened["ledger_seq"] == 0

    assert main(["--json", "audit", "--state", str(state), "--checkpoint", "--no-qr"]) == 0
    capsys.readouterr()

    assert (
        main(["--json", "trace", "--doc-id", "note", "--leaked", str(leaked),
              "--state", str(state)])
        == 0
    ), "a conclusive trace must exit 0"
    report = _json(capsys)

    assert report["verdict"] == "IDENTIFIED"
    assert report["accused"]["recipient_id"] == "r05"
    assert report["accused"]["p_bound"] < 1e-6, "gated on the provable bound"
    assert report["accused"]["p_value"] < 1e-6
    assert report["conclusive"] is True


def test_trace_never_reports_an_identification_without_a_p_value(workspace, capsys) -> None:
    _tmp, state, doc, _protect = workspace
    main(["--json", "open", "--doc-id", "note", "--recipient", "r01", "--state", str(state),
          "--out", str(state.parent / "l.txt")])
    capsys.readouterr()

    # the unmarked original: nobody should be named
    assert (
        main(["--json", "trace", "--doc-id", "note", "--leaked", str(doc), "--state", str(state)])
        == 1
    ), "an inconclusive trace must exit non-zero"
    report = _json(capsys)
    assert report["verdict"] == "NO IDENTIFICATION"
    assert report["conclusive"] is False
    assert report["accused"]["p_bound"] >= 1e-6, "still reported, with its bound"


def test_audit_tamper_detects_the_corruption_and_restore_undoes_it(workspace, capsys) -> None:
    _tmp, state, _doc, _protect = workspace
    main(["--json", "open", "--doc-id", "note", "--recipient", "r02", "--state", str(state),
          "--out", str(state.parent / "l2.txt")])
    capsys.readouterr()
    main(["--json", "audit", "--state", str(state), "--checkpoint", "--no-qr"])
    capsys.readouterr()

    assert main(["--json", "audit", "--state", str(state), "--tamper", "0", "--no-qr"]) == 1
    tampered = _json(capsys)
    assert tampered["chain"]["ok"] is False
    assert tampered["chain"]["first_bad_seq"] == 0
    assert tampered["tampered"]["before"] != tampered["tampered"]["after"]
    assert tampered["checkpoints"][0]["root_matches_entries"] is False, (
        "the witnessed root must stop reproducing"
    )

    assert main(["--json", "audit", "--state", str(state), "--restore", "--no-qr"]) == 0
    restored = _json(capsys)
    assert restored["restored"] is True
    assert restored["chain"]["ok"] is True
    assert restored["checkpoints"][0]["root_matches_entries"] is True


def test_audit_exports_a_qr_anchor(workspace, capsys) -> None:
    _tmp, state, _doc, _protect = workspace
    main(["--json", "open", "--doc-id", "note", "--recipient", "r03", "--state", str(state),
          "--out", str(state.parent / "l3.txt")])
    capsys.readouterr()

    assert main(["--json", "audit", "--state", str(state), "--checkpoint"]) == 0
    info = _json(capsys)
    assert len(info["anchors"]) == 1
    anchor = Path(info["anchors"][0])
    assert anchor.exists() and anchor.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert info["checkpoints"][0]["anchor"].startswith("PQFW1|")


def test_the_human_readable_output_renders_for_every_command(workspace, capsys) -> None:
    """No --json. Formatting bugs are demo-stoppers, so they are a test."""
    _tmp, state, doc, _protect = workspace
    leaked = state.parent / "human.txt"

    main(["open", "--doc-id", "note", "--recipient", "r09", "--state", str(state),
          "--out", str(leaked)])
    assert "ML-DSA-65" in capsys.readouterr().out

    main(["audit", "--state", str(state), "--checkpoint", "--no-qr"])
    assert "hash chain" in capsys.readouterr().out

    main(["trace", "--doc-id", "note", "--leaked", str(leaked), "--state", str(state)])
    out = capsys.readouterr().out
    assert "IDENTIFIED" in out and "r09" in out
    assert "false-accusation" in out and "z-score" in out
    assert "provable bound" in out and "Gaussian approximation" in out
    assert "runners-up" in out


def test_unknown_doc_id_is_an_error_not_a_traceback(workspace, capsys) -> None:
    _tmp, state, _doc, _protect = workspace
    assert main(["trace", "--doc-id", "nope", "--leaked", str(_doc_of(state)), "--state", str(state)]) == 2
    assert "error:" in capsys.readouterr().err


def _doc_of(state: Path) -> Path:
    return state.parent / "note.txt"
