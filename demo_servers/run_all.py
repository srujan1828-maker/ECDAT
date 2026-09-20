"""Master Launcher for 3 Dedicated Demo Websites.

Launches all 3 fully functional web applications simultaneously:
  1. Website 1: ApexPay (FinTech Banking & Card Checkout)   -> http://localhost:8081
  2. Website 2: MedVault (Healthcare Records & Rx Signing) -> http://localhost:8082
  3. Website 3: CipherCloud (Encrypted Enterprise Storage)  -> http://localhost:8083

Usage:
  python demo_servers/run_all.py
"""
import os
import subprocess
import sys
import time

DIR = os.path.dirname(os.path.abspath(__file__))

WEBSITES = [
    ("Website 1: ApexPay (Banking & Payment Portal)", os.path.join(DIR, "website1_apex_pay", "app.py"), "8081"),
    ("Website 2: MedVault (Clinical EHR & Prescription)", os.path.join(DIR, "website2_med_vault", "app.py"), "8082"),
    ("Website 3: CipherCloud (Encrypted Secret Vault)", os.path.join(DIR, "website3_cipher_cloud", "app.py"), "8083"),
]


def main():
    print("==================================================================")
    print("  ECDAT Live Demo Environment: Launching 3 Dedicated Websites")
    print("==================================================================")

    processes = []
    try:
        for name, script_path, port in WEBSITES:
            print(f"[*] Starting {name} on http://localhost:{port}...")
            p = subprocess.Popen(
                [sys.executable, script_path],
                cwd=os.path.dirname(script_path),
            )
            processes.append((name, p))
            time.sleep(0.5)

        print("\n[OK] All 3 dedicated websites are LIVE in your browser:")
        print("  +-------------------------------------------------------------+")
        print("  | 1. ApexPay Banking:     http://localhost:8081               |")
        print("  |    - Broken MD5 password hashing & 56-bit DES card vault    |")
        print("  +-------------------------------------------------------------+")
        print("  | 2. MedVault Healthcare: http://localhost:8082               |")
        print("  |    - Quantum-vulnerable 1024-bit RSA prescription keys      |")
        print("  +-------------------------------------------------------------+")
        print("  | 3. CipherCloud Storage: http://localhost:8083               |")
        print("  |    - 56-bit DES file encryption & weak MD5 integrity        |")
        print("  +-------------------------------------------------------------+")
        print("\n------------------------------------------------------------------")
        print("  Cloudflare Tunnel Setup (To expose any website publicly):")
        print("  Run in a separate terminal:")
        print("    cloudflared tunnel --url http://localhost:8081")
        print("    cloudflared tunnel --url http://localhost:8082")
        print("    cloudflared tunnel --url http://localhost:8083")
        print("------------------------------------------------------------------")
        print("  How to Demonstrate Live Patching:")
        print("  1. Preview Patches (Dry Run):")
        print("       python -m backend patch --path demo_servers")
        print("  2. Apply Patches (Creates .bak backups and fixes in-place):")
        print("       python -m backend patch --path demo_servers --apply")
        print("  3. Refresh http://localhost:8081, 8082, 8083 in browser to show")
        print("     the green 'SECURITY PATCHED' badges!")
        print("------------------------------------------------------------------")
        print("Press Ctrl+C to terminate all websites.\n")

        while True:
            time.sleep(1)
            for name, p in processes:
                if p.poll() is not None:
                    print(f"[!] Warning: {name} terminated unexpectedly with code {p.returncode}")

    except KeyboardInterrupt:
        print("\n[*] Stopping all demo websites...")
        for name, p in processes:
            p.terminate()
        print("[OK] All websites stopped cleanly.")


if __name__ == "__main__":
    main()
