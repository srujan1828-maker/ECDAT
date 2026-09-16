# ECDAT Backend - Dockerfile (FastAPI + Python 3.11)
FROM python:3.11-slim-trixie

# Prevent Python from buffering stdout/stderr and writing bytecode
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies if needed (e.g. OpenSSL/build essentials)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Fail the build if the image cannot enumerate the hybrid groups used by the scanner.
RUN openssl list -tls-groups | grep -q X25519MLKEM768

# Install python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application code
COPY . .

EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]

