"""
Procesador de Flujos (Stream Processor - AgroTrack-IoT).

Recibe lecturas de telemetría desde los gateways o simuladores, aplica control
de idempotencia por `event_id`, verifica la firma HMAC canónica, ordena y
evalúa excursiones térmicas en ventanas basadas en `event_timestamp` (tiempo de
evento), gestiona alertas con reconocimiento o escalamiento al coordinador y
expone métricas de latencia en milisegundos.
"""

import hashlib
import hmac
import json
import math
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Configuración por variables de entorno para adaptar persistencia, seguridad y umbrales sin tocar código.
DB_PATH = os.getenv("STREAM_DB_PATH", "/data/stream_state.db")
DEVICE_SECRET = os.getenv("DEVICE_SECRET", "agrotrack-edge-secret-key")
TEMP_THRESHOLD = float(os.getenv("TEMP_THRESHOLD", "5.0"))
WINDOW_MINUTES = float(os.getenv("WINDOW_MINUTES", "10.0"))
# Tiempo por defecto (180 s = 3 min) tras el cual una alerta sin confirmar escala al coordinador logístico.
ESCALATION_TIMEOUT_SECONDS = int(os.getenv("ESCALATION_TIMEOUT_SECONDS", "180"))

app = FastAPI(title="AgroTrack-IoT Stream Processor")


class TelemetryEvent(BaseModel):
    """Contrato de entrada de una lectura de telemetría enviada por un gateway o simulador."""

    event_id: str
    tenant_id: str
    device_id: str
    trip_id: str
    event_timestamp: str
    temperature: float
    humidity: float = 78.5
    lat: float = 4.5794
    lon: float = -74.2168
    door_open: bool = False
    prev_hash: str = "GENESIS"
    signature: str = ""
    gateway_sent_at: Optional[str] = None


class AlertAckRequest(BaseModel):
    """Datos enviados por el operador al reconocer una alerta activa."""

    acknowledged_by: str = "operator-central"
    notes: Optional[str] = None


def init_db() -> None:
    """Crea la carpeta de persistencia y las tablas `events` y `alerts` si aún no existen."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                trip_id TEXT NOT NULL,
                event_timestamp TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                temperature REAL NOT NULL,
                humidity REAL NOT NULL,
                lat REAL NOT NULL,
                lon REAL NOT NULL,
                door_open INTEGER NOT NULL,
                prev_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                signature_valid INTEGER NOT NULL,
                processing_latency_ms REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                trip_id TEXT NOT NULL,
                triggered_at TEXT NOT NULL,
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                max_temp REAL NOT NULL,
                escalation_after_sec INTEGER NOT NULL DEFAULT 180,
                status TEXT NOT NULL DEFAULT 'PENDING_ACK',
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                escalated_to TEXT,
                escalated_at TEXT,
                latency_ms REAL NOT NULL
            )
            """
        )
        conn.commit()


def verify_signature(ev: TelemetryEvent) -> bool:
    """Valida el HMAC-SHA256 del evento usando serialización JSON canónica y comparación segura."""
    if not ev.signature:
        return False
    body = {
        "event_id": ev.event_id,
        "tenant_id": ev.tenant_id,
        "device_id": ev.device_id,
        "trip_id": ev.trip_id,
        "event_timestamp": ev.event_timestamp,
        "temperature": ev.temperature,
        "humidity": ev.humidity,
        "lat": ev.lat,
        "lon": ev.lon,
        "door_open": ev.door_open,
    }
    # `sort_keys=True` y separadores compactos aseguran que emisor y verificador serialicen idénticamente.
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    message = f"{ev.prev_hash}|{canonical}".encode("utf-8")
    expected = hmac.new(
        DEVICE_SECRET.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, ev.signature)


def parse_iso(ts: str) -> datetime:
    """Convierte una marca de tiempo ISO-8601 a `datetime` consciente de zona horaria en UTC."""
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def evaluate_10min_window(
    conn: sqlite3.Connection, tenant_id: str, device_id: str, trip_id: str
) -> Optional[dict]:
    """Evalúa si existe una racha continua por encima de `TEMP_THRESHOLD` mayor a `WINDOW_MINUTES`.

    Ordena las lecturas del trayecto por `event_timestamp` (tiempo de evento) para que incluso
    lecturas enviadas tras una desconexión o fuera de orden se evalúen según cuándo ocurrieron.
    Si una lectura cae por debajo o igual al umbral, corta la racha continua actual.
    """
    rows = conn.execute(
        """
        SELECT event_timestamp, temperature
        FROM events
        WHERE tenant_id = ? AND device_id = ? AND trip_id = ?
        ORDER BY event_timestamp ASC
        """,
        (tenant_id, device_id, trip_id),
    ).fetchall()

    readings = [(parse_iso(ts), temp) for ts, temp in rows]
    n = len(readings)
    for i in range(n):
        start_dt, start_temp = readings[i]
        if start_temp <= TEMP_THRESHOLD:
            continue
        max_t = start_temp
        end_dt = start_dt
        for j in range(i + 1, n):
            curr_dt, curr_temp = readings[j]
            # Interrumpe la excursión continua si la temperatura vuelve a niveles seguros (`<= TEMP_THRESHOLD`).
            if curr_temp <= TEMP_THRESHOLD:
                break
            if curr_dt > end_dt:
                end_dt = curr_dt
            if curr_temp > max_t:
                max_t = curr_temp
            elapsed_min = (end_dt - start_dt).total_seconds() / 60.0
            if elapsed_min > WINDOW_MINUTES:
                return {
                    "window_start": start_dt.isoformat(),
                    "window_end": end_dt.isoformat(),
                    "max_temp": max_t,
                }
    return None


def run_escalation_check(
    conn: sqlite3.Connection, override_seconds: Optional[int] = None
) -> list[dict]:
    """Revisa alertas en estado `PENDING_ACK` y escala al coordinador si superan el tiempo límite.

    Admite `override_seconds` (por ejemplo, `force_seconds` en la demo o pruebas) para validar el
    escalamiento sin esperar 180 segundos en tiempo real.
    """
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    pending = conn.execute(
        """
        SELECT alert_id, triggered_at, escalation_after_sec, trip_id, device_id
        FROM alerts
        WHERE status = 'PENDING_ACK'
        """
    ).fetchall()

    escalated = []
    for alert_id, triggered_at, configured_sec, trip_id, device_id in pending:
        threshold_sec = (
            override_seconds if override_seconds is not None else configured_sec
        )
        elapsed_sec = (now_dt - parse_iso(triggered_at)).total_seconds()
        if elapsed_sec >= threshold_sec:
            conn.execute(
                """
                UPDATE alerts
                SET status = 'ESCALATED_TO_COORDINATOR',
                    escalated_to = 'logistics-coordinator',
                    escalated_at = ?
                WHERE alert_id = ?
                """,
                (now_iso, alert_id),
            )
            escalated.append(
                {
                    "alert_id": alert_id,
                    "trip_id": trip_id,
                    "device_id": device_id,
                    "elapsed_seconds": round(elapsed_sec, 2),
                    "threshold_seconds": threshold_sec,
                    "escalated_to": "logistics-coordinator",
                    "escalated_at": now_iso,
                }
            )
    return escalated


def percentile(values: list[float], p: float) -> float:
    """Calcula el percentil `p` (por ejemplo 50, 95 o 99) sobre una lista de latencias."""
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil((p / 100.0) * len(ordered)) - 1))
    return round(ordered[idx], 2)


@app.on_event("startup")
def on_startup() -> None:
    """Inicializa la base de datos al arrancar el microservicio."""
    init_db()


@app.get("/health")
def health() -> dict:
    """Entrega estado operativo y contadores resumidos de eventos y alertas."""
    with sqlite3.connect(DB_PATH) as conn:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alerts_cnt = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        escalated_cnt = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'ESCALATED_TO_COORDINATOR'"
        ).fetchone()[0]
    return {
        "service": "stream-processor",
        "status": "ok",
        "stored_events": total,
        "total_alerts": alerts_cnt,
        "escalated_alerts": escalated_cnt,
        "default_escalation_seconds": ESCALATION_TIMEOUT_SECONDS,
    }


@app.post("/ingest")
def ingest_event(ev: TelemetryEvent) -> dict:
    """Ingesta un evento de telemetría con deduplicación, validación de firma y evaluación de ventana.

    1. Verifica la firma HMAC.
    2. Ignora duplicados si `event_id` ya existe en `events`.
    3. Persiste el evento junto con su latencia de procesamiento en milisegundos.
    4. Si la firma es válida y `temperature > TEMP_THRESHOLD`, evalúa la ventana de 10 minutos
       y dispara una alerta única por `window_start` si aún no existe.
    """
    t0 = datetime.now(timezone.utc)
    sig_valid = verify_signature(ev)

    with sqlite3.connect(DB_PATH) as conn:
        # Clave primaria `event_id`: garantiza idempotencia ante reintentos o retransmisiones duplicadas.
        exists = conn.execute(
            "SELECT 1 FROM events WHERE event_id = ?", (ev.event_id,)
        ).fetchone()
        if exists:
            return {"status": "duplicate_ignored", "event_id": ev.event_id}

        t1 = datetime.now(timezone.utc)
        latency_ms = round((t1 - t0).total_seconds() * 1000.0, 2)

        conn.execute(
            """
            INSERT INTO events (
                event_id, tenant_id, device_id, trip_id, event_timestamp,
                ingested_at, temperature, humidity, lat, lon, door_open,
                prev_hash, signature, signature_valid, processing_latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ev.event_id,
                ev.tenant_id,
                ev.device_id,
                ev.trip_id,
                ev.event_timestamp,
                t1.isoformat(),
                ev.temperature,
                ev.humidity,
                ev.lat,
                ev.lon,
                1 if ev.door_open else 0,
                ev.prev_hash,
                ev.signature,
                1 if sig_valid else 0,
                latency_ms,
            ),
        )

        alert_triggered = None
        # Solo dispara alertas de excursión térmica sobre eventos cuya firma es válida.
        if sig_valid and ev.temperature > TEMP_THRESHOLD:
            win = evaluate_10min_window(
                conn, ev.tenant_id, ev.device_id, ev.trip_id
            )
            if win:
                # Evita generar múltiples alertas repetidas para la misma ventana de inicio (`window_start`).
                existing_alert = conn.execute(
                    """
                    SELECT alert_id FROM alerts
                    WHERE tenant_id = ? AND device_id = ? AND trip_id = ?
                      AND window_start = ?
                    """,
                    (ev.tenant_id, ev.device_id, ev.trip_id, win["window_start"]),
                ).fetchone()
                if not existing_alert:
                    t2 = datetime.now(timezone.utc)
                    alert_latency_ms = round((t2 - t0).total_seconds() * 1000.0, 2)
                    alert_id = f"alert-{ev.device_id}-{int(t2.timestamp())}"
                    conn.execute(
                        """
                        INSERT INTO alerts (
                            alert_id, tenant_id, device_id, trip_id,
                            triggered_at, window_start, window_end,
                            max_temp, escalation_after_sec, status, latency_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING_ACK', ?)
                        """,
                        (
                            alert_id,
                            ev.tenant_id,
                            ev.device_id,
                            ev.trip_id,
                            t2.isoformat(),
                            win["window_start"],
                            win["window_end"],
                            win["max_temp"],
                            ESCALATION_TIMEOUT_SECONDS,
                            alert_latency_ms,
                        ),
                    )
                    alert_triggered = {
                        "alert_id": alert_id,
                        "max_temp": win["max_temp"],
                        "status": "PENDING_ACK",
                        "escalation_after_sec": ESCALATION_TIMEOUT_SECONDS,
                        "latency_ms": alert_latency_ms,
                        "within_5s_sla": alert_latency_ms <= 5000.0,
                    }

        conn.commit()

    return {
        "status": "ingested",
        "event_id": ev.event_id,
        "signature_valid": sig_valid,
        "processing_latency_ms": latency_ms,
        "alert": alert_triggered,
    }


@app.post("/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: str, req: AlertAckRequest) -> dict:
    """Registra el reconocimiento operativo de una alerta si aún no fue escalada."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT status FROM alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alerta no encontrada")
        if row[0] == "ESCALATED_TO_COORDINATOR":
            return {
                "alert_id": alert_id,
                "status": row[0],
                "message": "La alerta ya había sido escalada al coordinador.",
            }
        conn.execute(
            """
            UPDATE alerts
            SET status = 'ACKNOWLEDGED',
                acknowledged_by = ?,
                acknowledged_at = ?
            WHERE alert_id = ?
            """,
            (req.acknowledged_by, now_iso, alert_id),
        )
        conn.commit()
    return {
        "alert_id": alert_id,
        "status": "ACKNOWLEDGED",
        "acknowledged_by": req.acknowledged_by,
        "acknowledged_at": now_iso,
    }


@app.post("/alerts/check-escalation")
def check_escalation(force_seconds: Optional[int] = None) -> dict:
    """Ejecuta explícitamente la verificación de escalamiento de alertas pendientes."""
    with sqlite3.connect(DB_PATH) as conn:
        escalated = run_escalation_check(conn, override_seconds=force_seconds)
        conn.commit()
    return {
        "escalated_count": len(escalated),
        "escalated_alerts": escalated,
    }


@app.get("/events/{trip_id}")
def get_trip_events(trip_id: str) -> dict:
    """Devuelve los eventos de un trayecto ordenados cronológicamente por `event_timestamp`."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT event_id, tenant_id, device_id, trip_id, event_timestamp,
                   temperature, humidity, lat, lon, door_open, prev_hash,
                   signature, signature_valid
            FROM events
            WHERE trip_id = ?
            ORDER BY event_timestamp ASC
            """,
            (trip_id,),
        ).fetchall()
    return {"trip_id": trip_id, "count": len(rows), "events": [dict(r) for r in rows]}


@app.get("/alerts")
def get_alerts(force_seconds: Optional[int] = None) -> dict:
    """Evalúa escalamientos pendientes, persiste cambios y lista todas las alertas."""
    with sqlite3.connect(DB_PATH) as conn:
        run_escalation_check(conn, override_seconds=force_seconds)
        conn.commit()
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY triggered_at DESC"
        ).fetchall()
    return {"count": len(rows), "alerts": [dict(r) for r in rows]}


@app.get("/metrics")
def get_metrics() -> dict:
    """Calcula percentiles p50, p95 y p99 de latencia de ingesta y generación de alertas."""
    with sqlite3.connect(DB_PATH) as conn:
        lat_rows = conn.execute(
            "SELECT processing_latency_ms FROM events"
        ).fetchall()
        alert_rows = conn.execute("SELECT latency_ms FROM alerts").fetchall()

    proc_lats = [r[0] for r in lat_rows]
    alert_lats = [r[0] for r in alert_rows]
    return {
        "total_events": len(proc_lats),
        "ingest_latency_ms": {
            "p50": percentile(proc_lats, 50),
            "p95": percentile(proc_lats, 95),
            "p99": percentile(proc_lats, 99),
        },
        "alert_latency_ms": {
            "count": len(alert_lats),
            "p50": percentile(alert_lats, 50),
            "p95": percentile(alert_lats, 95),
            "p99": percentile(alert_lats, 99),
            "sla_target_ms": 5000.0,
        },
    }