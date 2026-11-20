import json
import math
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

GATEWAY_URL = "http://localhost:8003"
STREAM_URL = "http://localhost:8001"

NOMINAL_TARGET_MSG_S = 186.7
RECONNECT_PEAK_MSG_S = 2400.0


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil((p / 100.0) * len(ordered)) - 1))
    return round(ordered[idx], 2)


def send_reading(i: int, trip_id: str) -> tuple[bool, float]:
    payload = {
        "tenant_id": "tenant-cundinamarca-01",
        "device_id": f"truck-load-{(i % 50) + 1:03d}",
        "trip_id": trip_id,
        "temperature": 3.8 if i % 5 != 0 else 5.6,
        "humidity": 79.0 + (i % 10) * 0.5,
        "lat": 4.5794,
        "lon": -74.2168,
        "door_open": bool(i % 12 == 0),
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{GATEWAY_URL}/telemetry",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
        return True, (time.perf_counter() - t0) * 1000.0
    except (urllib.error.URLError, TimeoutError):
        return False, (time.perf_counter() - t0) * 1000.0


def run_batch(label: str, total_requests: int, workers: int, trip_id: str) -> dict:
    latencies_ms: list[float] = []
    ok_count = 0
    err_count = 0

    t_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(send_reading, i, trip_id) for i in range(total_requests)
        ]
        for fut in as_completed(futures):
            ok, lat = fut.result()
            latencies_ms.append(lat)
            if ok:
                ok_count += 1
            else:
                err_count += 1
    elapsed_s = time.perf_counter() - t_start
    throughput = ok_count / elapsed_s if elapsed_s > 0 else 0.0

    summary = {
        "scenario": label,
        "completed_ok": ok_count,
        "errors": err_count,
        "total_requests": total_requests,
        "workers": workers,
        "elapsed_s": round(elapsed_s, 2),
        "throughput_req_s": round(throughput, 2),
        "p50_ms": percentile(latencies_ms, 50),
        "p95_ms": percentile(latencies_ms, 95),
        "p99_ms": percentile(latencies_ms, 99),
    }

    print(f"\n=== {label} ===")
    print(
        f"Completados: {ok_count}/{total_requests} | Errores: {err_count} | "
        f"Tiempo: {elapsed_s:.2f} s | Throughput local: {throughput:.1f} req/s"
    )
    print(
        f"Latencia e2e gateway->stream (ms): "
        f"p50={summary['p50_ms']}, p95={summary['p95_ms']}, p99={summary['p99_ms']}"
    )
    return summary


def main() -> None:
    base_res = run_batch(
        "PRUEBA BASE (300 envios, 15 workers)",
        total_requests=300,
        workers=15,
        trip_id="trip-load-base-01",
    )
    stress_res = run_batch(
        "PRUEBA DE ESTRES / EXAGERADA (1500 envios, 40 workers)",
        total_requests=1500,
        workers=40,
        trip_id="trip-load-stress-01",
    )

    with urllib.request.urlopen(f"{STREAM_URL}/metrics", timeout=10) as resp:
        stream_metrics = json.loads(resp.read().decode("utf-8"))

    print("\n=== EXTRAPOLACION Y REFERENCIA DE diseno (ADR-02 / CAPACIDAD) ===")
    print(f"Tasa nominal objetivo (5000 camiones + 200 cuartos frios): {NOMINAL_TARGET_MSG_S} msg/s")
    print(f"Pico de reconexion tras apagón rural: {RECONNECT_PEAK_MSG_S} msg/s")
    print(
        f"Factor vs tasa nominal (estrés local {stress_res['throughput_req_s']} req/s): "
        f"{stress_res['throughput_req_s'] / NOMINAL_TARGET_MSG_S:.2f}x"
    )
    print("\nMetricas internas stream-processor:", json.dumps(stream_metrics, indent=2))


if __name__ == "__main__":
    main()