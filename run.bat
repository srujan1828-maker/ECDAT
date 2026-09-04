@echo off
title ECDAT Next.js + FastAPI Orchestrator
echo =====================================================================
echo  ECDAT: Enterprise Cryptographic Discovery & Analysis Tool (SIH26164)
echo  National Technical Research Organisation (NTRO) Prototype
echo =====================================================================
echo.

IF NOT EXIST ".venv\Scripts\activate.bat" (
    echo [*] Initializing virtual environment...
    python -m venv .venv
)

echo [*] Installing backend dependencies...
.venv\Scripts\pip.exe install -r backend\requirements.txt

echo [*] Starting FastAPI Backend on port 8000...
start cmd /k "cd backend && ..\.venv\Scripts\uvicorn.exe main:app --port 8000 --reload"

echo [*] Installing frontend dependencies...
cd frontend
call npm install

echo [*] Starting Next.js Frontend on port 3000...
start cmd /k "npm run dev"

echo [*] ECDAT is starting... Backend on :8000, Frontend on :3000
pause
