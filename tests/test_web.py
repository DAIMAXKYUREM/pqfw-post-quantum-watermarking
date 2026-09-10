"""The demo front end, driven through its own HTTP API.

A demo that breaks on stage is worse than no demo, so the whole click-path is a test:
enrol, protect, open, prove the key binding, trace, collude, tamper, restore.

It also pins the two properties that make a *public* demo defensible: one browser's
session cannot reach another's, and the limits actually reject oversized input.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "web"))

fastapi_testclient = pytest.importorskip("fastapi.testclient")
from app import MAX_DOCUMENT_BYTES, MAX_RECIPIENTS, app  # noqa: E402

DOC = (
    "MINISTRY OF SOCIAL JUSTICE AND EMPOWERMENT. This note is released to the "
    "distribution list at annexe A and to no other reader. It summarises findings "
    "from the quarterly review of tender processes across the four regional offices, "
    "together with the recommendations of the review committee and a provisional "
    "timetable for remedial action. Recipients are reminded that each copy released "
    "under this cover is individually accountable to the person named against it on "
    "the distribution list, and that its onward transmission in whole or in part is "
    "a breach of the terms under which it was released to them in the first place.\n"
) * 3


@pytest.fixture()
def client():
    with fastapi_testclient.TestClient(app) as c:
        yield c


@pytest.fixture()
def ready(client):
    assert client.post("/api/enroll", json={"recipients": 10}).status_code == 200
    protect = client.post("/api/protect", json={"document": DOC, "coalition": 2})
    assert protect.status_code == 200, protect.text
    return client, protect.json()


# ---------------------------------------------------------------------------


def test_the_page_and_the_algorithm_report_load(client) -> None:
    page = client.get("/")
    assert page.status_code == 200
    assert "Post-Quantum Forensic Watermarking" in page.text

    # Every control the front-end script drives must exist in the markup. Pinning the
    # ids rather than the prose means the page can be restyled freely, and a redesign
    # that drops a button still fails here instead of in front of an audience.
    for element_id in (
        "algs", "n", "bEnroll", "oEnroll", "carrier", "coalition", "doc", "bProtect",
        "oProtect", "who", "bOpen", "bProve", "oOpen", "leak", "file", "bTrace",
        "bTraceFile", "c1", "c2", "c3", "strategy", "bCollude", "oTrace",
        "bAudit", "bTamper", "bRestore", "oAudit", "s1", "s2", "s3", "s4", "s5",
    ):
        assert f'id="{element_id}"' in page.text, f"the page is missing #{element_id}"

    info = client.get("/api/info").json()
    assert info["algorithms"]["kem"] == "ML-KEM-768"
    assert info["algorithms"]["sig"] == "ML-DSA-65"
    assert set(info["carriers"]) == {"text-zwsp", "pdf-kern"}


def test_protect_reports_the_shared_ciphertext_and_the_reachable_bound(ready) -> None:
    _client, protect = ready
    assert protect["size"]["per_recipient_bytes"] < protect["size"]["public_bytes"]
    assert protect["achievable_eps"] < 1e-6
    assert protect["slots"] == protect["carrier_capacity"]
    assert len(protect["recipient_ids"]) == 10


def test_open_then_trace_identifies_the_recipient(ready) -> None:
    client, _ = ready
    opened = client.post("/api/open", json={"recipient": "r06"}).json()
    assert opened["ledger_seq"] == 0
    assert opened["preview"] is not None

    report = client.post("/api/trace-text", json={"leaked": opened["preview"]}).json()
    assert report["verdict"] == "IDENTIFIED"
    assert report["accused"]["recipient_id"] == "r06"
    assert report["accused"]["p_bound"] < 1e-6
    assert report["ledger"]["chain_ok"] is True
    assert report["ledger"]["checkpoint_valid"] is True


def test_the_visible_text_is_the_original_document(ready) -> None:
    """What the page claims next to the highlighted marks: strip them and it is the
    source, character for character."""
    client, _ = ready
    opened = client.post("/api/open", json={"recipient": "r02"}).json()
    assert opened["visible_text"] == DOC
    assert opened["preview"] != DOC, "the copy itself must differ"


def test_the_key_binding_demo_really_refuses(ready) -> None:
    """The endpoint behind the page's central claim. If this ever returns
    other_variant_decrypts=True the whole project is broken."""
    client, _ = ready
    client.post("/api/open", json={"recipient": "r03"})
    proof = client.post("/api/prove-key-binding", json={"recipient": "r03", "slot": 17}).json()
    assert proof["issued_variant_decrypts"] is True
    assert proof["other_variant_decrypts"] is False
    assert proof["other_variant_error"] == "InvalidTag"
    assert proof["variant_they_hold"] != proof["variant_they_do_not"]


def test_an_unmarked_document_names_nobody(ready) -> None:
    client, _ = ready
    client.post("/api/open", json={"recipient": "r01"})
    report = client.post("/api/trace-text", json={"leaked": DOC}).json()
    assert report["verdict"] == "NO IDENTIFICATION"
    assert report["conclusive"] is False


def test_collusion_endpoint_reports_forced_and_free_slots(ready) -> None:
    client, _ = ready
    result = client.post(
        "/api/collude", json={"recipients": ["r00", "r04", "r08"], "strategy": "majority"}
    ).json()
    assert result["slots_forced"] + result["slots_free"] == result["slots"]
    assert result["slots_forced"] > 0, "three codewords will agree somewhere"
    assert len(result["ranked"]) >= 3


def test_tamper_then_restore_through_the_api(ready) -> None:
    client, _ = ready
    client.post("/api/open", json={"recipient": "r05"})

    clean = client.post("/api/audit", json={"action": "verify"}).json()
    assert clean["chain"]["ok"] is True

    broken = client.post("/api/audit", json={"action": "tamper", "seq": 0}).json()
    assert broken["chain"]["ok"] is False
    assert broken["checkpoints"][0]["root_matches_entries"] is False

    restored = client.post("/api/audit", json={"action": "restore"}).json()
    assert restored["chain"]["ok"] is True
    assert restored["changed"]["restored"] is True


def test_two_decryptions_by_one_person_are_distinct_over_the_api(ready) -> None:
    client, _ = ready
    first = client.post("/api/open", json={"recipient": "r04"}).json()
    second = client.post("/api/open", json={"recipient": "r04"}).json()

    assert first["session_id"] != second["session_id"]
    assert first["doc_hash"] != second["doc_hash"]
    assert second["sessions_left"] < first["sessions_left"]

    for opened in (first, second):
        report = client.post("/api/trace-text", json={"leaked": opened["preview"]}).json()
        assert report["accused"]["recipient_id"] == "r04"
        assert report["session_id"] == opened["session_id"], "resolves to the right event"


def test_the_validator_network_replicates_and_reaches_quorum(ready) -> None:
    client, _ = ready
    client.post("/api/open", json={"recipient": "r00"})
    audit = client.post("/api/audit", json={"action": "verify"}).json()

    consensus = audit["consensus"]
    assert consensus["nodes"] == 3 and consensus["quorum"] == 2
    assert consensus["diverged"] == [] and consensus["valid"] == [0, 1, 2]
    assert consensus["committed"] is True and consensus["ok"] is True


def test_compromising_one_validator_is_detected_and_out_voted_over_the_api(ready) -> None:
    """The requirement in one call: a single compromised account changes nothing."""
    client, _ = ready
    client.post("/api/open", json={"recipient": "r01"})
    client.post("/api/audit", json={"action": "verify"})

    hit = client.post("/api/audit", json={"action": "compromise", "node": 1, "seq": 0}).json()
    consensus = hit["changed"]["consensus"]
    assert consensus["diverged"] == [1], "the tampered replica must stand out"
    assert consensus["valid"] == [0, 2], "and fail its own verification"
    assert consensus["honest_majority"] is True, "the rest still make quorum"
    assert hit["ok"] is False

    healed = client.post("/api/audit", json={"action": "heal"}).json()
    assert healed["changed"]["healed"] == [1]
    assert healed["consensus"]["ok"] is True
    assert healed["ok"] is True


def test_a_pdf_copy_round_trips_through_upload(ready) -> None:
    client, _ = ready
    assert client.post("/api/protect", json={"document": DOC, "carrier": "pdf-kern"}).status_code == 200
    opened = client.post("/api/open", json={"recipient": "r07"}).json()
    assert opened["is_pdf"] is True and opened["preview"] is None

    download = client.get(opened["download"])
    assert download.status_code == 200
    assert download.content.startswith(b"%PDF-")

    report = client.post(
        "/api/trace", files={"leaked": ("leak.pdf", download.content, "application/pdf")}
    ).json()
    assert report["accused"]["recipient_id"] == "r07"
    assert report["verdict"] == "IDENTIFIED"


# ---------------------------------------------------------------------------
# public-demo hygiene
# ---------------------------------------------------------------------------


def test_sessions_are_isolated_from_each_other() -> None:
    """Two browsers must not see each other's documents, recipients or ledgers."""
    with fastapi_testclient.TestClient(app) as a, fastapi_testclient.TestClient(app) as b:
        a.post("/api/enroll", json={"recipients": 4})
        a.post("/api/protect", json={"document": DOC})
        a_open = a.post("/api/open", json={"recipient": "r01"}).json()

        # b has enrolled nothing, so b cannot trace a's leak or fetch a's copy
        assert b.post("/api/trace-text", json={"leaked": a_open["preview"]}).status_code == 409
        assert b.get("/api/copy/r01").status_code == 409

        b.post("/api/enroll", json={"recipients": 4})
        assert b.get("/api/copy/r01").status_code == 404, "b's own session has no such copy"


def test_the_limits_reject_oversized_input(client) -> None:
    client.post("/api/enroll", json={"recipients": 4})
    assert client.post("/api/protect", json={"document": "x" * (MAX_DOCUMENT_BYTES + 1)}).status_code == 400
    assert client.post("/api/protect", json={"document": "   "}).status_code == 400
    assert client.post("/api/enroll", json={"recipients": MAX_RECIPIENTS + 1}).status_code == 400
    assert client.post("/api/enroll", json={"recipients": 1}).status_code == 400


def test_acting_before_enrolling_is_a_clean_error(client) -> None:
    assert client.post("/api/protect", json={"document": DOC}).status_code == 409
    assert client.post("/api/open", json={"recipient": "r00"}).status_code == 409
    assert client.post("/api/trace-text", json={"leaked": "x"}).status_code == 409


def test_unknown_recipient_and_carrier_are_rejected(ready) -> None:
    client, _ = ready
    assert client.post("/api/open", json={"recipient": "nobody"}).status_code == 400
    assert client.post("/api/protect", json={"document": DOC, "carrier": "nope"}).status_code == 400
    assert client.get("/api/copy/..%2F..%2Fetc").status_code in (400, 404)


def test_health_reports_the_real_primitives(client) -> None:
    health = client.get("/api/health").json()
    assert health["ok"] is True
    assert health["algorithms"]["kem"] == "ML-KEM-768"


def test_health_reports_which_build_is_serving(client) -> None:
    """A deploy has to be verifiable from outside.

    Without this the only way to tell whether a push actually reached the host was to
    guess from behaviour, which is how a stale container goes unnoticed.
    """
    build = client.get("/api/health").json()["build"]
    assert build["commit"]
    assert build["text_addressing"] == "content-anchored"
