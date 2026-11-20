# AgroTrack-IoT — Prototipo Arquitectónico Ejecutable (Entregable B)

Prototipo funcional de corte vertical en **Python (FastAPI)** y **Docker Compose** para validar empíricamente los escenarios críticos del sistema **AgroTrack-IoT** (trazabilidad y cadena de frío en logística agrícola).

## Arquitectura del Prototipo (3 Contenedores)

1. **`gateway-sim` (puerto `8003`):** Simula un Gateway embarcado en el borde con buffer local en SQLite (`store-and-forward`), control de conectividad (`online`/`offline`), firma/encadenamiento HMAC-SHA256 por lectura y reenvío por lotes sin duplicados al reconectar.
2. **`stream-processor` (puerto `8001`):** Recibe eventos, valida firma, deduplica por `event_id`, evalúa la ventana temporal de **10 minutos** sobre temperaturas **mayores a 5 °C** usando `event_timestamp` (tolerando datos tardíos/desordenados), registra alertas y calcula percentiles de latencia (`p50`, `p95`, `p99`).
3. **`cert-service` (puerto `8002`):** Consulta las lecturas del trayecto, verifica la integridad y cadena de hashes, genera certificados de trazabilidad (o los invalida ante alteración registrando el evento en `/audit`) bajo el marco de la **Ley 527 de 1999**.

## Despliegue

Desde la carpeta `agrotrack-iot-prototype`:

```bash
docker compose up --build -d
docker compose ps
```

## Pruebas Funcionales y de Carga

- **Corte de red y *store-and-forward*:** Cambiar `gateway-sim` a `online: false` (`POST /network`), enviar lecturas con `POST /telemetry/burst` y volver a `online: true` para verificar el envío por lotes y la alerta de más de 5 °C durante más de 10 minutos.
- **Integridad y no repudio:** Enviar una lectura con `tamper_signature: true` (`POST /telemetry`) y generar el certificado (`POST /certificates/generate`) para verificar el estado `INVALIDATED_TAMPERING_DETECTED` y el registro en `GET /audit`.
- **Prueba de carga y percentiles:** Ejecutar `python load_test.py` para obtener `p50`, `p95` y `p99`.

## Declaración de Uso de IA y Autoría

## Desarrollado por **Juan Camilo Barrera Puerto** (Universidad de Cundinamarca — Extensión Soacha) para el Examen de Suficiencia de Estructura y Arquitectura de Software (`ADOr001`), con apoyo asistido de IA generativa para estructuración, pruebas y revisión técnica, validado y ejecutado localmente por el autor.
