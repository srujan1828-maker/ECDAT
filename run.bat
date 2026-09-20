@echo off
setlocal enabledelayedexpansion
title ECDAT Next.js + FastAPI Orchestrator
echo =====================================================================
echo  ECDAT: Enterprise Cryptographic Discovery & Analysis Tool (SIH26164)
echo  National Technical Research Organisation (NTRO) Prototype
echo =====================================================================
echo.

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] Python is not installed or not in your PATH. Please install Python 3.10+
    pause
    exit /b 1
)

where npm >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [!] Node.js / npm is not installed or not in your PATH. Please install Node.js 18+
    pause
    exit /b 1
)

IF NOT EXIST ".venv\Scripts\activate.bat" (
    echo [*] Initializing virtual environment in .venv...
    python -m venv .venv
)

echo [*] Installing backend dependencies...
.venv\Scripts\python.exe -m pip install -q --upgrade pip
.venv\Scripts\pip.exe install -q -r backend\requirements.txt

echo [*] Starting FastAPI Backend on port 8000...
start "ECDAT Backend (Port 8000)" cmd /k "cd backend && ..\.venv\Scripts\uvicorn.exe main:app --host 127.0.0.1 --port 8000 --reload"

echo [*] Installing frontend dependencies...
cd frontend
call npm install --silent

echo [*] Starting Next.js Frontend on port 3000...
start "ECDAT Frontend (Port 3000)" cmd /k "npm run dev"
cd ..

echo.
echo =====================================================================
echo  [+] ECDAT is running!
echo      - Frontend UI:  http://localhost:3000
echo      - Backend API:  http://127.0.0.1:8000
echo      - Swagger Docs: http://127.0.0.1:8000/docs
echo =====================================================================
echo.
pause
