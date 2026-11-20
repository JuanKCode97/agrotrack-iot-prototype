import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

DB_PATH = "/data/certificates.db"
STREAM_PROCESSOR_URL = os.getenv(
    "STREAM_PROCESSOR_URL", "http://stream-processor:8001"
)
DEVICE_SECRET = os.getenv("DEVICE_SECRET", "agrotrack-edge-secret-key")
MAX_CERTIFIED_TEMP = 4.0

app = FastAPI(title="AgroTrack-IoT Certificate Service")


class CertificateRequest(BaseModel):
    trip_id: str
    buyer_name: str = "International Cold-Chain Buyer"


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS certificates (
                cert_id TEXT PRIMARY KEY,
                trip_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                buyer_name TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL,
                readings_count INTEGER NOT NULL,
                max_temp REAL,
                cert_hash TEXT NOT NULL,
                issued_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                audit_id TEXT PRIMARY KEY,
                trip_id TEXT NOT NULL,
                event_id TEXT,
                finding TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def verify_event_hmac(ev: dict) -> bool:
    sig = ev.get("signature", "")
    prev_hash = ev.get("prev_hash", "")
    if not sig or not prev_hash:
        return False
    body = {
        "event_id": ev["event_id"],
        "tenant_id": ev["tenant_id"],
        "device_id": ev["device_id"],
        "trip_id": ev["trip_id"],
        "event_timestamp": ev["event_timestamp"],
        "temperature": ev["temperature"],
        "humidity": ev["humidity"],
        "lat": ev["lat"],
        "lon": ev["lon"],
        "door_open": bool(ev["door_open"]),
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    message = f"{prev_hash}|{canonical}".encode("utf-8")
    expected = hmac.new(
        DEVICE_SECRET.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict:
    with sqlite3.connect(DB_PATH) as conn:
        certs = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
        audits = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    return {
        "service": "cert-service",
        "status": "ok",
        "certificates_issued": certs,
        "audit_entries": audits,
    }


@app.post("/certificates/generate")
async def generate_certificate(req: CertificateRequest) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.get(f"{STREAM_PROCESSOR_URL}/events/{req.trip_id}")
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"No se pudo consultar stream-processor: {exc}",
            ) from exc

    if resp.status_code != 200:
        raise HTTPException(status_code=404, detail="Trayecto no encontrado")

    data = resp.json()
    events = data.get("events", [])
    if not events:
        raise HTTPException(
            status_code=400,
            detail="No hay lecturas registradas para emitir certificado",
        )

    tampered_events = []
    expected_prev = None
    temps = []
    now_iso = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        for idx, ev in enumerate(events):
            temps.append(ev["temperature"])
            sig_ok = verify_event_hmac(ev) and bool(ev.get("signature_valid", 1))
            chain_ok = True if idx == 0 else (ev.get("prev_hash") == expected_prev)

            if not sig_ok or not chain_ok:
                tampered_events.append(ev["event_id"])
                conn.execute(
                    """
                    INSERT INTO audit_log (audit_id, trip_id, event_id, finding, recorded_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        req.trip_id,
                        ev["event_id"],
                        f"Tampering/signature mismatch (sig_ok={sig_ok}, chain_ok={chain_ok})",
                        now_iso,
                    ),
                )

            expected_prev = hashlib.sha256(
                f"{ev['prev_hash']}|{ev['signature']}".encode("utf-8")
            ).hexdigest()

        max_temp = max(temps) if temps else None
        if tampered_events:
            status = "INVALIDATED_TAMPERING_DETECTED"
            reason = (
                f"Certificado invalidado por alteración o firma inválida en "
                f"{len(tampered_events)} lectura(s); registrado en auditoría."
            )
        elif max_temp is not None and max_temp > MAX_CERTIFIED_TEMP:
            status = "VALID_WITH_THERMAL_EXCURSION"
            reason = (
                f"Firma e integridad verificadas (Ley 527 de 1999); se registró "
                f"temperatura máxima de {max_temp}°C (umbral comprador: {MAX_CERTIFIED_TEMP}°C)."
            )
        else:
            status = "VALID_CERTIFIED"
            reason = (
                f"Cadena de custodia íntegra y verificada (Ley 527 de 1999); "
                f"temperatura máxima registrada: {max_temp}°C."
            )

        cert_id = f"CERT-{uuid.uuid4().hex[:8].upper()}"
        cert_payload = f"{cert_id}|{req.trip_id}|{status}|{max_temp}|{now_iso}"
        cert_hash = hashlib.sha256(cert_payload.encode("utf-8")).hexdigest()

        tenant_id = events[0]["tenant_id"]
        device_id = events[0]["device_id"]

        conn.execute(
            """
            INSERT INTO certificates (
                cert_id, trip_id, tenant_id, device_id, buyer_name,
                status, reason, readings_count, max_temp, cert_hash, issued_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cert_id,
                req.trip_id,
                tenant_id,
                device_id,
                req.buyer_name,
                status,
                reason,
                len(events),
                max_temp,
                cert_hash,
                now_iso,
            ),
        )
        conn.commit()

    return {
        "cert_id": cert_id,
        "trip_id": req.trip_id,
        "tenant_id": tenant_id,
        "device_id": device_id,
        "buyer_name": req.buyer_name,
        "status": status,
        "reason": reason,
        "readings_count": len(events),
        "max_temp": max_temp,
        "tampered_event_ids": tampered_events,
        "cert_hash": cert_hash,
        "legal_framework": "Ley 527 de 1999 (integridad y no repudio)",
        "issued_at": now_iso,
    }


@app.get("/certificates")
def list_certificates() -> dict:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM certificates ORDER BY issued_at DESC"
        ).fetchall()
    return {"count": len(rows), "certificates": [dict(r) for r in rows]}


@app.get("/audit")
def list_audit() -> dict:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY recorded_at DESC"
        ).fetchall()
    return {"count": len(rows), "audit_entries": [dict(r) for r in rows]}