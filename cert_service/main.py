import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

DB_PATH = os.getenv("CERT_DB_PATH", "/data/certificates.db")
PDF_DIR = os.getenv("CERT_PDF_DIR", "/data/certs_pdf")
STREAM_PROCESSOR_URL = os.getenv(
    "STREAM_PROCESSOR_URL", "http://stream-processor:8001"
)
DEVICE_SECRET = os.getenv("DEVICE_SECRET", "agrotrack-edge-secret-key")
MAX_CERTIFIED_TEMP = float(os.getenv("MAX_CERTIFIED_TEMP", "4.0"))

app = FastAPI(title="AgroTrack-IoT Certificate Service")


class CertificateRequest(BaseModel):
    trip_id: str
    buyer_name: str = "International Cold-Chain Buyer"


class PaymentCheckoutRequest(BaseModel):
    cert_id: str
    amount_usd: float = 15.0
    payment_method: str = "CARD_GATEWAY_SIM"
    payer_email: str = "buyer@agroexport.co"


def build_simple_pdf_bytes(lines: list[str]) -> bytes:
    """Genera un PDF válido sin requerir librerías externas."""
    escaped = []
    for line in lines:
        clean = (
            line.replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
            .replace("°", " deg ")
        )
        escaped.append(clean)

    content_lines = ["BT", "/F1 11 Tf", "50 740 Td", "16 TL"]
    for idx, text in enumerate(escaped):
        if idx == 0:
            content_lines.append(f"({text}) Tj")
        else:
            content_lines.append(f"T* ({text}) Tj")
    content_lines.append("ET")
    stream_data = "\n".join(content_lines).encode("latin-1", errors="replace")

    objs = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        f"5 0 obj\n<< /Length {len(stream_data)} >>\nstream\n".encode("ascii")
        + stream_data
        + b"\nendstream\nendobj\n",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objs:
        offsets.append(len(pdf))
        pdf.extend(obj)

    xref_pos = len(pdf)
    pdf.extend(f"xref\n0 {len(objs) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        pdf.extend(f"{off:010d} 00000 n \n".encode("ascii"))

    pdf.extend(
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(pdf)


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(PDF_DIR, exist_ok=True)
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
                pdf_path TEXT,
                payment_status TEXT NOT NULL DEFAULT 'PENDING_PAYMENT',
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS payments (
                payment_id TEXT PRIMARY KEY,
                cert_id TEXT NOT NULL,
                amount_usd REAL NOT NULL,
                payment_method TEXT NOT NULL,
                payer_email TEXT NOT NULL,
                status TEXT NOT NULL,
                provider_ref TEXT NOT NULL,
                processed_at TEXT NOT NULL
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
        payments = conn.execute("SELECT COUNT(*) FROM payments").fetchone()[0]
    return {
        "service": "cert-service",
        "status": "ok",
        "certificates_issued": certs,
        "audit_entries": audits,
        "payments_processed": payments,
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
                f"Certificado invalidado por alteracion o firma invalida en "
                f"{len(tampered_events)} lectura(s); registrado en auditoria."
            )
        elif max_temp is not None and max_temp > MAX_CERTIFIED_TEMP:
            status = "VALID_WITH_THERMAL_EXCURSION"
            reason = (
                f"Cadena de custodia verificada (Ley 527 de 1999); temperatura "
                f"maxima registrada: {max_temp} C (umbral comprador: {MAX_CERTIFIED_TEMP} C)."
            )
        else:
            status = "VALID_CERTIFIED"
            reason = (
                f"Cadena de custodia integra y verificada (Ley 527 de 1999); "
                f"temperatura maxima registrada: {max_temp} C."
            )

        cert_id = f"CERT-{uuid.uuid4().hex[:8].upper()}"
        cert_payload = f"{cert_id}|{req.trip_id}|{status}|{max_temp}|{now_iso}"
        cert_hash = hashlib.sha256(cert_payload.encode("utf-8")).hexdigest()

        tenant_id = events[0]["tenant_id"]
        device_id = events[0]["device_id"]

        pdf_path = None
        if status != "INVALIDATED_TAMPERING_DETECTED":
            pdf_bytes = build_simple_pdf_bytes(
                [
                    "AGROTRACK-IOT - CERTIFICADO DE TRAZABILIDAD DE CADENA DE FRIO",
                    "Marco normativo: Ley 527 de 1999 (Integridad y No Repudio)",
                    f"Certificado ID: {cert_id}",
                    f"Trayecto (trip_id): {req.trip_id}",
                    f"Inquilino (tenant_id): {tenant_id} | Dispositivo: {device_id}",
                    f"Comprador: {req.buyer_name}",
                    f"Estado: {status}",
                    f"Lecturas analizadas: {len(events)} | Temp. maxima: {max_temp} C",
                    f"Hash SHA-256: {cert_hash}",
                    f"Emitido: {now_iso}",
                ]
            )
            pdf_path = os.path.join(PDF_DIR, f"{cert_id}.pdf")
            with open(pdf_path, "wb") as f:
                f.write(pdf_bytes)

        conn.execute(
            """
            INSERT INTO certificates (
                cert_id, trip_id, tenant_id, device_id, buyer_name,
                status, reason, readings_count, max_temp, cert_hash,
                pdf_path, payment_status, issued_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_PAYMENT', ?)
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
                pdf_path,
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
        "pdf_available": pdf_path is not None,
        "pdf_download_url": f"/certificates/{cert_id}/pdf" if pdf_path else None,
        "payment_status": "PENDING_PAYMENT",
        "legal_framework": "Ley 527 de 1999 (integridad y no repudio)",
        "issued_at": now_iso,
    }


@app.get("/certificates/{cert_id}/pdf")
def download_certificate_pdf(cert_id: str) -> Response:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT status, pdf_path FROM certificates WHERE cert_id = ?",
            (cert_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Certificado no encontrado")
    status, pdf_path = row
    if not pdf_path or not os.path.exists(pdf_path):
        raise HTTPException(
            status_code=409,
            detail=f"PDF no disponible para certificado en estado {status}",
        )
    with open(pdf_path, "rb") as f:
        data = f.read()
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{cert_id}.pdf"'},
    )


@app.post("/payments/checkout")
def checkout_payment(req: PaymentCheckoutRequest) -> dict:
    now_iso = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        cert_row = conn.execute(
            "SELECT status FROM certificates WHERE cert_id = ?", (req.cert_id,)
        ).fetchone()
        if not cert_row:
            raise HTTPException(status_code=404, detail="Certificado no encontrado")
        if cert_row[0] == "INVALIDATED_TAMPERING_DETECTED":
            raise HTTPException(
                status_code=400,
                detail="No se puede procesar pago sobre un certificado invalidado por alteración",
            )

        payment_id = f"PAY-{uuid.uuid4().hex[:8].upper()}"
        provider_ref = f"GW-SIM-{int(datetime.now(timezone.utc).timestamp())}"
        conn.execute(
            """
            INSERT INTO payments (
                payment_id, cert_id, amount_usd, payment_method,
                payer_email, status, provider_ref, processed_at
            ) VALUES (?, ?, ?, ?, ?, 'APPROVED', ?, ?)
            """,
            (
                payment_id,
                req.cert_id,
                req.amount_usd,
                req.payment_method,
                req.payer_email,
                provider_ref,
                now_iso,
            ),
        )
        conn.execute(
            "UPDATE certificates SET payment_status = 'PAID' WHERE cert_id = ?",
            (req.cert_id,),
        )
        conn.commit()

    return {
        "payment_id": payment_id,
        "cert_id": req.cert_id,
        "amount_usd": req.amount_usd,
        "payment_method": req.payment_method,
        "status": "APPROVED",
        "provider_ref": provider_ref,
        "processed_at": now_iso,
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