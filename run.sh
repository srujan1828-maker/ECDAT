#!/usr/bin/env bash
# ECDAT Launch Script for Linux / macOS
set -e

echo "====================================================================="
echo " ECDAT: Enterprise Cryptographic Discovery & Analysis Tool (SIH26164)"
echo " National Technical Research Organisation (NTRO) Prototype"
echo "====================================================================="

if [ ! -d ".venv" ]; then
    echo "[*] Initializing virtual environment..."
    python3 -m venv .venv
fi

echo "[*] Installing backend dependencies..."
.venv/bin/pip install -r backend/requirements.txt

echo "[*] Starting FastAPI Backend on port 8000 (background)..."
cd backend
../.venv/bin/uvicorn main:app --port 8000 &
BACKEND_PID=$!
cd ..

echo "[*] Installing frontend dependencies..."
cd frontend
npm install

echo "[*] Starting Next.js Frontend on port 3000..."
npm run dev &
FRONTEND_PID=$!

echo "[*] ECDAT is running. Press Ctrl+C to stop."
trap "kill $BACKEND_PID $FRONTEND_PID" EXIT
wait
