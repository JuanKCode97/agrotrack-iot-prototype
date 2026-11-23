# Imagen base oficial ligera de Python 3.11 sobre Debian slim para reducir superficie de 
# ataque y tamaño de capa.
FROM python:3.11-slim

# Define el directorio de trabajo dentro del contenedor donde residirá la aplicación y sus dependencias.
WORKDIR /app

# Copia primero el manifiesto de dependencias para aprovechar la caché de capas de Docker
# y evitar reinstalar paquetes si solo cambia main.py.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia el código fuente del servicio de certificación (validación de integridad, PDF, auditoría y pagos).
COPY main.py .

# Inicia el servidor ASGI Uvicorn exponiendo la API FastAPI en todas las interfaces (0.0.0.0) del puerto 8002.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]