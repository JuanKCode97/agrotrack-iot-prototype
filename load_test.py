import json
import math
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

GATEWAY_URL = "http://localhost:8003"
STREAM_URL = "http://localhost:8001"


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil((p / 100.0) * len(ordered)) - 1))
    return round(ordered[idx], 2)


def send_reading(i: int) -> float:
    payload = {
        "tenant_id": "tenant-cundinamarca-01",
        "device_id": f"truck-load-{(i % 50) + 1:03d}",
        "trip_id": "trip-load-test-01",
        "temperature": 3.8 if i % 5 != 0 else 5.6,
        "humidity": 80.0,
        "lat": 4.5794,
        "lon": -74.2168,
        "door_open": False,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{GATEWAY_URL}/telemetry",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()
    return (time.perf_counter() - t0) * 1000.0


def main() -> None:
    total_requests = 300
    workers = 15
    latencies_ms: list[float] = []

    t_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(send_reading, i) for i in range(total_requests)]
        for fut in as_completed(futures):
            latencies_ms.append(fut.result())
    elapsed_s = time.perf_counter() - t_start

    with urllib.request.urlopen(f"{STREAM_URL}/metrics", timeout=10) as resp:
        stream_metrics = json.loads(resp.read().decode("utf-8"))

    print("=== RESUMEN PRUEBA DE CARGA (ENTREGABLE B) ===")
    print(f"Envios completados: {len(latencies_ms)}/{total_requests}")
    print(f"Tiempo total: {elapsed_s:.2f} s | Throughput local: {len(latencies_ms)/elapsed_s:.1f} req/s")
    print(
        "Latencia end-to-end gateway->stream (ms): "
        f"p50={percentile(latencies_ms, 50)}, "
        f"p95={percentile(latencies_ms, 95)}, "
        f"p99={percentile(latencies_ms, 99)}"
    )
    print("Metricas internas stream-processor:", json.dumps(stream_metrics, indent=2))


if __name__ == "__main__":
    main()