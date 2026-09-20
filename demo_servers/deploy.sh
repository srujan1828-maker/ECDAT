#!/usr/bin/env bash
set -e
echo "====================================================================="
echo "  ECDAT 3 Demo Websites - 5-Minute Deployment System"
echo "====================================================================="
echo ""
echo "Select deployment mode:"
echo "  [1] 1-Click Cloudflare Live Public HTTPS Tunnels (Zero Setup)"
echo "  [2] Docker Compose Containers (Local / Production Server)"
echo "  [3] Run All 3 Locally on ports 8081, 8082, 8083"
echo "  [4] Render.com Blueprint Instructions (Cloud Hosted)"
echo ""
read -p "Enter choice [1-4, default=1]: " choice
choice=${choice:-1}

if [ "$choice" = "1" ]; then
    echo "[*] Launching Cloudflare Public HTTPS Deployer..."
    node tunnel_deploy.js
elif [ "$choice" = "2" ]; then
    echo "[*] Launching Docker Compose..."
    docker compose up -d --build
    echo "[+] Docker containers started!"
    echo "    - ApexPay:     http://localhost:8081"
    echo "    - MedVault:    http://localhost:8082"
    echo "    - CipherCloud: http://localhost:8083"
elif [ "$choice" = "3" ]; then
    echo "[*] Starting all 3 servers locally..."
    node run_all.js
elif [ "$choice" = "4" ]; then
    echo "Link repository to Render.com and use demo_servers/render.yaml."
fi
