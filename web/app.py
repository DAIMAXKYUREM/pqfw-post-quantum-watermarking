"""A demo front end over the real PQFW library.

Everything on the page is produced by the same code the CLI and the tests drive: real
ML-KEM-768 key encapsulation, real ML-DSA-65 receipts, real AES-256-GCM variant
encryption, real Tardos scoring, a real hash chain. Nothing is mocked or pre-baked.

Each browser gets its own sealed store under a temporary directory, keyed by a random
session id in a cookie. Sessions are evicted oldest-first, so a public deployment
cannot be made to fill the disk.

The server still makes no outbound network calls. It is a viewer for an offline
system, not a service the offline system depends on.
"""

from __future__ import annotations

import os
import shutil
import secrets
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from fastapi import Body, Cookie, FastAPI, HTTPException, Response, UploadFile, File
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from pqfw import package as pkg
from pqfw import pqc, tardos, workflow
from pqfw.carrier import available as available_carriers
from pqfw.store import Store

# Public demo limits. Generous enough to show the real behaviour, small enough that a
# stranger cannot turn the box over.
MAX_DOCUMENT_BYTES = 40_000
MAX_RECIPIENTS = 30
MAX_SLOTS = 1_500
MAX_SESSIONS = 40
SESSION_TTL_SECONDS = 60 * 60 * 3

ROOT = Path(__file__).resolve().parent
SESSION_ROOT = Path(tempfile.gettempdir()) / "pqfw-web-sessions"

app = FastAPI(title="PQFW demo", docs_url=None, redoc_url=None)


@dataclass
class Session:
    session_id: str
    created: float = field(default_factory=time.time)

    @property
    def path(self) -> Path:
        return SESSION_ROOT / self.session_id

    def store(self) -> Store:
        if (self.path / "distributor.sealed").exists():
            return Store.open(self.path)
        return Store(self.path)


_SESSIONS: dict[str, Session] = {}


def _evict() -> None:
    now = time.time()
    stale = [s for s in _SESSIONS.values() if now - s.created > SESSION_TTL_SECONDS]
    while len(_SESSIONS) - len(stale) > MAX_SESSIONS:
        oldest = min(_SESSIONS.values(), key=lambda s: s.created)
        if oldest in stale:
            break
        stale.append(oldest)
    for session in stale:
        _SESSIONS.pop(session.session_id, None)
        shutil.rmtree(session.path, ignore_errors=True)


def _session(session_id: str | None, response: Response | None = None) -> Session:
    _evict()
    if session_id and session_id in _SESSIONS:
        return _SESSIONS[session_id]
    new_id = secrets.token_urlsafe(16)
    session = Session(session_id=new_id)
    session.path.mkdir(parents=True, exist_ok=True)
    _SESSIONS[new_id] = session
    if response is not None:
        response.set_cookie(
            "pqfw_session", new_id, httponly=True, samesite="lax", max_age=SESSION_TTL_SECONDS
        )
    return session


def _require(session_id: str | None) -> Session:
    if not session_id or session_id not in _SESSIONS:
        raise HTTPException(status_code=409, detail="Session expired. Start again at step 1.")
    return _SESSIONS[session_id]


# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse((ROOT / "static" / "index.html").read_text(encoding="utf-8"))


@app.get("/api/info")
def info() -> dict[str, Any]:
    return {
        "algorithms": pqc.alg_report(),
        "carriers": available_carriers(),
        "limits": {
            "document_bytes": MAX_DOCUMENT_BYTES,
            "recipients": MAX_RECIPIENTS,
            "slots": MAX_SLOTS,
        },
    }


@app.post("/api/enroll")
def api_enroll(
    response: Response,
    payload: dict[str, Any] = Body(default={}),
    pqfw_session: str | None = Cookie(default=None),
) -> dict[str, Any]:
    recipients = int(payload.get("recipients", 12))
    if not 2 <= recipients <= MAX_RECIPIENTS:
        raise HTTPException(400, f"recipients must be between 2 and {MAX_RECIPIENTS}")

    session = _session(None, response)  # a fresh enroll always starts a clean store
    shutil.rmtree(session.path, ignore_errors=True)
    session.path.mkdir(parents=True, exist_ok=True)

    store = Store(session.path)
    result = workflow.enroll(store, recipients=recipients, witnesses=3, threshold=2)
    return {"session": session.session_id, **result}


@app.post("/api/protect")
def api_protect(
    payload: dict[str, Any] = Body(...),
    pqfw_session: str | None = Cookie(default=None),
) -> dict[str, Any]:
    session = _require(pqfw_session)
    text = str(payload.get("document", ""))
    source = text.encode("utf-8")
    if not source.strip():
        raise HTTPException(400, "the document is empty")
    if len(source) > MAX_DOCUMENT_BYTES:
        raise HTTPException(400, f"documents are capped at {MAX_DOCUMENT_BYTES:,} bytes here")

    carrier = str(payload.get("carrier", "text-zwsp"))
    if carrier not in available_carriers():
        raise HTTPException(400, f"unknown carrier {carrier!r}")

    store = session.store()
    if not store.recipient_ids():
        raise HTTPException(409, "no recipients enrolled; run step 1 first")

    try:
        result = workflow.protect(
            store,
            source,
            doc_id="demo",
            carrier_name=carrier,
            coalition=int(payload.get("coalition", 3)),
            eps1=float(payload.get("eps", 1e-6)),
            slots=min(int(payload["slots"]), MAX_SLOTS) if payload.get("slots") else None,
            rng=np.random.default_rng(),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    return {**result.to_json(), "recipient_ids": store.recipient_ids()}


@app.post("/api/open")
def api_open(
    payload: dict[str, Any] = Body(...),
    pqfw_session: str | None = Cookie(default=None),
) -> dict[str, Any]:
    session = _require(pqfw_session)
    store = session.store()
    recipient_id = str(payload.get("recipient", ""))
    if recipient_id not in store.recipient_ids():
        raise HTTPException(400, f"unknown recipient {recipient_id!r}")

    try:
        result = workflow.open_as(store, "demo", recipient_id)
    except (KeyError, FileNotFoundError) as exc:
        raise HTTPException(409, f"nothing to open yet: {exc}") from exc
    workflow.checkpoint(store)

    record = store.doc("demo")
    is_pdf = record.carrier == "pdf-kern"
    out = session.path / "copies" / f"{recipient_id}.{'pdf' if is_pdf else 'txt'}"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(result.document)

    return {
        "recipient_id": recipient_id,
        "session_id": result.session_id,
        "sessions_left": result.sessions_left,
        "doc_hash": result.doc_hash,
        "ledger_seq": result.ledger_seq,
        "entry_hash": result.entry_hash,
        "bytes": len(result.document),
        "is_pdf": is_pdf,
        "download": f"/api/copy/{recipient_id}",
        "preview": None if is_pdf else result.document.decode("utf-8", errors="replace"),
        "visible_text": _visible(record.carrier, result.document),
    }


def _visible(carrier: str, document: bytes) -> str | None:
    """What a reader sees: the copy with every marking artefact removed.

    Shown next to the raw copy so a viewer can confirm for themselves that the two
    differ only in characters that render as nothing.
    """
    if carrier != "text-zwsp":
        return None
    from pqfw.carriers.text import CARRIER

    return CARRIER.strip_marks(document).decode("utf-8", errors="replace")


@app.get("/api/copy/{recipient_id}")
def api_copy(recipient_id: str, pqfw_session: str | None = Cookie(default=None)) -> FileResponse:
    session = _require(pqfw_session)
    if not recipient_id.isalnum():
        raise HTTPException(400, "bad recipient id")
    for suffix, media in (("pdf", "application/pdf"), ("txt", "text/plain; charset=utf-8")):
        candidate = session.path / "copies" / f"{recipient_id}.{suffix}"
        if candidate.exists():
            return FileResponse(candidate, media_type=media, filename=candidate.name)
    raise HTTPException(404, "that copy has not been opened in this session")


@app.post("/api/prove-key-binding")
def api_prove_key_binding(
    payload: dict[str, Any] = Body(...),
    pqfw_session: str | None = Cookie(default=None),
) -> dict[str, Any]:
    """Demonstrate the central security claim live, on this session's real package.

    Takes the recipient's actual variant key for a slot and tries it against the
    rendering they were not issued. The AEAD tag check refuses. This is the whole
    argument for why the fingerprint is not something their software chose to apply.
    """
    from cryptography.exceptions import InvalidTag

    session = _require(pqfw_session)
    store = session.store()
    recipient_id = str(payload.get("recipient", ""))
    if recipient_id not in store.recipient_ids():
        raise HTTPException(400, f"unknown recipient {recipient_id!r}")

    record = store.doc("demo")
    package = pkg.DistributionPackage.load(store.package_path("demo"))
    device = store.recipient_device(recipient_id)

    sessions = record.sessions_for(recipient_id)
    if not sessions:
        raise HTTPException(400, f"no decryption credentials issued to {recipient_id!r}")
    session_id = sessions[0]
    bundle = pkg.unwrap_bundle(package, session_id, device["kem_sk"])

    index = int(payload.get("slot", 0)) % package.m
    held = int(record.X[record.index_of(session_id)][index])
    other = 1 - held

    issued_ok = False
    try:
        pqc.aead_decrypt(
            bundle.vks[index],
            package.variant_blobs[index][held],
            aad=pkg.variant_aad("demo", index, held),
        )
        issued_ok = True
    except InvalidTag:
        pass

    other_error = None
    try:
        pqc.aead_decrypt(
            bundle.vks[index],
            package.variant_blobs[index][other],
            aad=pkg.variant_aad("demo", index, other),
        )
    except InvalidTag as exc:
        other_error = type(exc).__name__

    return {
        "recipient_id": recipient_id,
        "session_id": session_id,
        "slot": index,
        "variant_they_hold": held,
        "variant_they_do_not": other,
        "issued_variant_decrypts": issued_ok,
        "other_variant_decrypts": other_error is None,
        "other_variant_error": other_error,
    }


@app.post("/api/trace")
async def api_trace(
    leaked: UploadFile | None = File(default=None),
    pqfw_session: str | None = Cookie(default=None),
) -> JSONResponse:
    session = _require(pqfw_session)
    if leaked is None:
        raise HTTPException(400, "no file uploaded")
    data = await leaked.read(MAX_DOCUMENT_BYTES * 4 + 1)
    if len(data) > MAX_DOCUMENT_BYTES * 4:
        raise HTTPException(400, "that upload is too large for the demo")

    store = session.store()
    try:
        report = workflow.trace_leak(store, "demo", data, alpha=1e-6)
    except KeyError as exc:
        raise HTTPException(409, f"nothing protected in this session yet: {exc}") from exc
    return JSONResponse(report.to_json())


@app.post("/api/trace-text")
def api_trace_text(
    payload: dict[str, Any] = Body(...),
    pqfw_session: str | None = Cookie(default=None),
) -> dict[str, Any]:
    session = _require(pqfw_session)
    text = str(payload.get("leaked", ""))
    store = session.store()
    try:
        report = workflow.trace_leak(store, "demo", text.encode("utf-8"), alpha=1e-6)
    except KeyError as exc:
        raise HTTPException(409, f"nothing protected in this session yet: {exc}") from exc
    return report.to_json()


@app.post("/api/collude")
def api_collude(
    payload: dict[str, Any] = Body(...),
    pqfw_session: str | None = Cookie(default=None),
) -> dict[str, Any]:
    """Splice several recipients' copies together and trace the result.

    Where the coalition disagrees they may choose; where they agree they are stuck,
    because none of them holds the key for the other rendering. That constraint is
    enforced by the package, not assumed of the attacker.
    """
    session = _require(pqfw_session)
    store = session.store()
    ids = [str(x) for x in payload.get("recipients", [])]
    strategy = str(payload.get("strategy", "majority"))
    if len(ids) < 2:
        raise HTTPException(400, "a coalition needs at least two members")
    if strategy not in tardos.STRATEGIES:
        raise HTTPException(400, f"unknown strategy {strategy!r}")

    record = store.doc("demo")
    unknown = [r for r in ids if not record.sessions_for(r)]
    if unknown:
        raise HTTPException(400, f"unknown recipients: {', '.join(unknown)}")

    # Each colluder brings the copy from their first decryption credential.
    coalition_sessions = [record.sessions_for(r)[0] for r in ids]
    rows = np.array(
        [record.X[record.index_of(s)] for s in coalition_sessions], dtype=np.uint8
    )
    forged = tardos.collude(rows, strategy, np.random.default_rng())

    from pqfw.trace import trace_bits

    ranked = trace_bits(forged, "demo", store, alpha=1e-6)
    agreed = int((rows.min(axis=0) == rows.max(axis=0)).sum())
    return {
        "coalition": ids,
        "coalition_sessions": coalition_sessions,
        "strategy": strategy,
        "slots": int(rows.shape[1]),
        "slots_forced": agreed,
        "slots_free": int(rows.shape[1]) - agreed,
        "ranked": [s.to_json() for s in ranked[:6]],
        "caught": [s.recipient_id for s in ranked[:3] if s.recipient_id in ids],
    }


@app.post("/api/audit")
def api_audit(
    payload: dict[str, Any] = Body(default={}),
    pqfw_session: str | None = Cookie(default=None),
) -> dict[str, Any]:
    session = _require(pqfw_session)
    store = session.store()

    action = str(payload.get("action", "verify"))
    changed: dict[str, Any] | None = None
    if action == "tamper":
        try:
            changed = workflow.tamper(store, int(payload.get("seq", 0)))
        except IndexError as exc:
            raise HTTPException(400, str(exc)) from exc
    elif action == "restore":
        changed = {"restored": workflow.restore(store)}
    elif action == "checkpoint":
        cp = workflow.checkpoint(store)
        changed = {"checkpoint": cp.index if cp else None}

    return {**workflow.audit(store), "action": action, "changed": changed}


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "sessions": len(_SESSIONS), "algorithms": pqc.alg_report()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 7860)))
