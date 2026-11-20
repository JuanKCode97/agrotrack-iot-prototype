import hashlib
import hmac
import json
import math
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

DB_PATH = "/data/stream_state.db"
DEVICE_SECRET = os.getenv("DEVICE_SECRET", "agrotrack-edge-secret-key")
TEMP_THRESHOLD = 5.0
WINDOW_MINUTES = 10.0

app = FastAPI(title="AgroTrack-IoT Stream Processor")


class TelemetryEvent(BaseModel):
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


def init_db() -> None:
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
                escalation_after_min INTEGER NOT NULL DEFAULT 3,
                status TEXT NOT NULL DEFAULT 'PENDING_ACK',
                latency_ms REAL NOT NULL
            )
            """
        )
        conn.commit()


def verify_signature(ev: TelemetryEvent) -> bool:
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
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    message = f"{ev.prev_hash}|{canonical}".encode("utf-8")
    expected = hmac.new(
        DEVICE_SECRET.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, ev.signature)


def parse_iso(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def evaluate_10min_window(
    conn: sqlite3.Connection, tenant_id: str, device_id: str, trip_id: str
) -> Optional[dict]:
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


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil((p / 100.0) * len(ordered)) - 1))
    return round(ordered[idx], 2)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict:
    with sqlite3.connect(DB_PATH) as conn:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alerts_cnt = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    return {
        "service": "stream-processor",
        "status": "ok",
        "stored_events": total,
        "total_alerts": alerts_cnt,
    }


@app.post("/ingest")
def ingest_event(ev: TelemetryEvent) -> dict:
    t0 = datetime.now(timezone.utc)
    sig_valid = verify_signature(ev)

    with sqlite3.connect(DB_PATH) as conn:
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
        if sig_valid and ev.temperature > TEMP_THRESHOLD:
            win = evaluate_10min_window(
                conn, ev.tenant_id, ev.device_id, ev.trip_id
            )
            if win:
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
                            max_temp, escalation_after_min, status, latency_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 3, 'PENDING_ACK', ?)
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
                            alert_latency_ms,
                        ),
                    )
                    alert_triggered = {
                        "alert_id": alert_id,
                        "max_temp": win["max_temp"],
                        "escalation_after_min": 3,
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


@app.get("/events/{trip_id}")
def get_trip_events(trip_id: str) -> dict:
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
def get_alerts() -> dict:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY triggered_at DESC"
        ).fetchall()
    return {"count": len(rows), "alerts": [dict(r) for r in rows]}


@app.get("/metrics")
def get_metrics() -> dict:
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