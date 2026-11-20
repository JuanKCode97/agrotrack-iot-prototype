import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

DB_PATH = os.getenv("GATEWAY_DB_PATH", "/data/gateway_buffer.db")
STREAM_PROCESSOR_URL = os.getenv("STREAM_PROCESSOR_URL", "http://localhost:8001")
CERT_SERVICE_URL = os.getenv("CERT_SERVICE_URL", "http://localhost:8002")
DEVICE_SECRET = os.getenv("DEVICE_SECRET", "agrotrack-edge-secret-key")

app = FastAPI(title="AgroTrack-IoT Gateway Simulator")


class TelemetryInput(BaseModel):
    tenant_id: str = "tenant-cundinamarca-01"
    device_id: str = "truck-001"
    trip_id: str = "trip-2026-11-19-a"
    temperature: float
    humidity: float = 78.5
    lat: float = 4.5794
    lon: float = -74.2168
    door_open: bool = False
    event_timestamp: Optional[str] = None
    tamper_signature: bool = False


class NetworkState(BaseModel):
    online: bool


class BurstRequest(BaseModel):
    tenant_id: str = "tenant-cundinamarca-01"
    device_id: str = "truck-001"
    trip_id: str = "trip-2026-11-19-a"
    count: int = 25
    temperature: float = 6.2
    humidity: float = 78.5
    lat: float = 4.5794
    lon: float = -74.2168
    door_open: bool = False
    step_seconds: int = 30
    start_minutes_ago: int = 15


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS telemetry_queue (
                event_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                trip_id TEXT NOT NULL,
                event_timestamp TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                sent INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT OR IGNORE INTO state (key, value) VALUES ('online', 'true')"
        )
        conn.execute(
            "INSERT OR IGNORE INTO state (key, value) VALUES ('last_hash', 'GENESIS')"
        )
        conn.commit()


def is_online() -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT value FROM state WHERE key = 'online'").fetchone()
        return row[0] == "true" if row else True


def set_online(online: bool) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE state SET value = ? WHERE key = 'online'",
            ("true" if online else "false",),
        )
        conn.commit()


def get_and_update_hash(canonical_payload: str) -> tuple[str, str]:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT value FROM state WHERE key = 'last_hash'").fetchone()
        prev_hash = row[0] if row else "GENESIS"
        message = f"{prev_hash}|{canonical_payload}".encode("utf-8")
        signature = hmac.new(
            DEVICE_SECRET.encode("utf-8"), message, hashlib.sha256
        ).hexdigest()
        new_hash = hashlib.sha256(f"{prev_hash}|{signature}".encode("utf-8")).hexdigest()
        conn.execute(
            "UPDATE state SET value = ? WHERE key = 'last_hash'", (new_hash,)
        )
        conn.commit()
        return prev_hash, signature


def store_reading(item: TelemetryInput) -> dict:
    event_id = str(uuid.uuid4())
    event_ts = item.event_timestamp or datetime.now(timezone.utc).isoformat()
    created_at = datetime.now(timezone.utc).isoformat()

    body = {
        "event_id": event_id,
        "tenant_id": item.tenant_id,
        "device_id": item.device_id,
        "trip_id": item.trip_id,
        "event_timestamp": event_ts,
        "temperature": item.temperature,
        "humidity": item.humidity,
        "lat": item.lat,
        "lon": item.lon,
        "door_open": item.door_open,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    prev_hash, signature = get_and_update_hash(canonical)
    if item.tamper_signature:
        signature = "0" * 64

    record = {
        **body,
        "prev_hash": prev_hash,
        "signature": signature,
        "gateway_sent_at": None,
    }

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO telemetry_queue (
                event_id, tenant_id, device_id, trip_id, event_timestamp,
                payload_json, signature, sent, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
            """,
            (
                event_id,
                item.tenant_id,
                item.device_id,
                item.trip_id,
                event_ts,
                json.dumps(record),
                signature,
                created_at,
            ),
        )
        conn.commit()
    return record


async def flush_queue() -> dict:
    if not is_online():
        return {"flushed": 0, "status": "offline_buffered"}

    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT event_id, payload_json FROM telemetry_queue
            WHERE sent = 0
            ORDER BY event_timestamp ASC
            """
        ).fetchall()

    if not rows:
        return {"flushed": 0, "status": "nothing_to_send"}

    sent_ids = []
    errors = 0
    t_start = time.perf_counter()

    async with httpx.AsyncClient(timeout=5.0) as client:
        for event_id, payload_json in rows:
            payload = json.loads(payload_json)
            payload["gateway_sent_at"] = datetime.now(timezone.utc).isoformat()
            try:
                resp = await client.post(
                    f"{STREAM_PROCESSOR_URL}/ingest", json=payload
                )
                if resp.status_code == 200:
                    sent_ids.append(event_id)
                else:
                    errors += 1
            except httpx.HTTPError:
                errors += 1
                break

    if sent_ids:
        with sqlite3.connect(DB_PATH) as conn:
            conn.executemany(
                "UPDATE telemetry_queue SET sent = 1 WHERE event_id = ?",
                [(eid,) for eid in sent_ids],
            )
            conn.commit()

    elapsed_ms = round((time.perf_counter() - t_start) * 1000, 2)
    return {
        "flushed": len(sent_ids),
        "errors": errors,
        "elapsed_ms": elapsed_ms,
        "status": "flushed",
    }


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict:
    with sqlite3.connect(DB_PATH) as conn:
        pending = conn.execute(
            "SELECT COUNT(*) FROM telemetry_queue WHERE sent = 0"
        ).fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM telemetry_queue").fetchone()[0]
    return {
        "service": "gateway-sim",
        "online": is_online(),
        "pending_events": pending,
        "total_events": total,
    }


@app.post("/network")
async def update_network(state: NetworkState) -> dict:
    set_online(state.online)
    flush_result = await flush_queue() if state.online else {"flushed": 0}
    return {"online": state.online, "flush_result": flush_result}


@app.post("/telemetry")
async def receive_telemetry(item: TelemetryInput) -> dict:
    record = store_reading(item)
    if is_online():
        flush_res = await flush_queue()
        return {"mode": "online", "event": record, "flush": flush_res}
    return {"mode": "offline_store_and_forward", "event": record}


@app.post("/telemetry/burst")
async def simulate_burst(req: BurstRequest) -> dict:
    base_time = time.time() - (req.start_minutes_ago * 60)
    created = 0
    for i in range(req.count):
        ts = datetime.fromtimestamp(
            base_time + (i * req.step_seconds), tz=timezone.utc
        ).isoformat()
        store_reading(
            TelemetryInput(
                tenant_id=req.tenant_id,
                device_id=req.device_id,
                trip_id=req.trip_id,
                temperature=req.temperature,
                humidity=req.humidity,
                lat=req.lat,
                lon=req.lon,
                door_open=req.door_open,
                event_timestamp=ts,
            )
        )
        created += 1

    flush_res = await flush_queue() if is_online() else {"flushed": 0}
    return {"created": created, "online": is_online(), "flush": flush_res}


@app.post("/flush")
async def manual_flush() -> dict:
    return await flush_queue()