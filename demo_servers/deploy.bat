@echo off
setlocal
title ECDAT Demo Websites - 5-Minute Deployer
echo =====================================================================
echo   ECDAT 3 Demo Websites - 5-Minute Deployment System
echo =====================================================================
echo.
echo Select deployment mode:
echo   [1] 1-Click Cloudflare Live Public HTTPS Tunnels (Zero Setup)
echo   [2] Docker Compose Containers (Local / Production Server)
echo   [3] Run All 3 Locally on ports 8081, 8082, 8083
echo   [4] Render.com Blueprint Instructions (Cloud Hosted)
echo.
set /p choice="Enter choice [1-4, default=1]: "
if "%choice%"=="" set choice=1

if "%choice%"=="1" (
    echo.
    echo [*] Launching Cloudflare Public HTTPS Deployer...
    node tunnel_deploy.js
    goto end
)

if "%choice%"=="2" (
    echo.
    echo [*] Launching Docker Compose...
    docker compose up -d --build
    echo.
    echo [+] Docker containers started!
    echo     - ApexPay:     http://localhost:8081
    echo     - MedVault:    http://localhost:8082
    echo     - CipherCloud: http://localhost:8083
    pause
    goto end
)

if "%choice%"=="3" (
    echo.
    echo [*] Starting all 3 servers locally...
    node run_all.js
    goto end
)

if "%choice%"=="4" (
    echo.
    echo =====================================================================
    echo   Render.com 1-Click Cloud Deployment:
    echo =====================================================================
    echo   1. Push your repo to GitHub.
    echo   2. Go to https://dashboard.render.com/blueprints
    echo   3. Click "New Blueprint Instance" and link your GitHub repo.
    echo   4. Select "demo_servers/render.yaml".
    echo   Render will deploy all 3 web services with custom HTTPS domains!
    echo =====================================================================
    pause
    goto end
)

:end
