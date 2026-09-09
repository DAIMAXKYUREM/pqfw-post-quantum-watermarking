"""PQFW makes no network calls at runtime.

The definition of done says "runs with the network interface disabled". Asserting it
here is stronger than checking it by hand once: the socket layer is replaced with one
that refuses every operation, and then the entire pipeline -- enroll, protect, open,
trace, audit -- has to run to completion anyway.

There is no cloud KMS, no timestamping authority, no public chain, and no telemetry.
An air-gapped deployment is the intended one, and the QR checkpoint anchor exists so
that even the external-anchoring story needs no network.
"""

from __future__ import annotations

import socket

import numpy as np
import pytest

from pqfw import workflow
from pqfw.ledger import FixedClock
from pqfw.store import Store

SOURCE = (
    "AIR GAPPED DEPLOYMENT NOTE. The assessment attached to this cover is released "
    "to the distribution list and to nobody else. Every copy is individually "
    "accountable to the person named against it, and the issuing office is able to "
    "establish which copy has appeared outside the intended readership without any "
    "recourse to an external service, a network connection, or a third party of any "
    "kind whatsoever, which is a deliberate property of the design and not an "
    "accident of how this particular prototype happens to have been assembled here."
).encode("utf-8")


class _NoNetwork(socket.socket):
    def __init__(self, *args: object, **kwargs: object) -> None:
        raise OSError("network access is not permitted in PQFW")


@pytest.fixture()
def no_network(monkeypatch):
    """Refuse sockets at the lowest level available from Python."""
    monkeypatch.setattr(socket, "socket", _NoNetwork)
    monkeypatch.setattr(
        socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(OSError("blocked"))
    )
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(OSError("blocked"))
    )

    with pytest.raises(OSError):
        socket.socket()
    return True


def test_the_whole_pipeline_runs_with_no_network(no_network, tmp_path) -> None:
    store = Store(tmp_path / "state", clock=FixedClock())

    workflow.enroll(store, recipients=8, witnesses=3, threshold=2)
    workflow.protect(
        store, SOURCE, doc_id="airgap", rng=np.random.default_rng(3), coalition=2
    )
    opened = workflow.open_as(store, "airgap", "r05")
    workflow.checkpoint(store)

    report = workflow.trace_leak(store, "airgap", opened.document)
    assert report.accused is not None and report.accused.recipient_id == "r05"
    assert report.conclusive is True

    audit = workflow.audit(store)
    assert audit["chain"]["ok"] is True
    assert audit["checkpoints"][0]["valid"] is True


def test_the_pdf_carrier_needs_no_network_either(no_network, tmp_path) -> None:
    store = Store(tmp_path / "state", clock=FixedClock())
    workflow.enroll(store, recipients=6, witnesses=3, threshold=2)
    workflow.protect(
        store,
        SOURCE,
        doc_id="airgap-pdf",
        carrier_name="pdf-kern",
        rng=np.random.default_rng(4),
        coalition=2,
    )
    opened = workflow.open_as(store, "airgap-pdf", "r02")
    workflow.checkpoint(store)

    report = workflow.trace_leak(store, "airgap-pdf", opened.document)
    assert report.accused is not None and report.accused.recipient_id == "r02"
    assert report.conclusive is True


def test_the_qr_anchor_is_produced_offline(no_network, tmp_path) -> None:
    """The external-anchoring story: a printed root, not a call to a timestamping
    service."""
    from pqfw import ledger as L

    store = Store(tmp_path / "state", clock=FixedClock())
    workflow.enroll(store, recipients=3, witnesses=3, threshold=2)
    workflow.protect(store, SOURCE, doc_id="anchor", rng=np.random.default_rng(5), coalition=2)
    workflow.open_as(store, "anchor", "r00")
    cp = workflow.checkpoint(store)
    assert cp is not None

    out = L.export_checkpoint_qr(cp, tmp_path / "anchor.png")
    assert out.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
