"""
TC-05 — Header Spoofing Attack Demo
Demonstrates that X-Forwarded-For cannot bypass an active IP blacklist.

Step 1: Blacklist the real IP by triggering the rate limit (brute force).
Step 2: Attempt to bypass the block by injecting fake IPs via X-Forwarded-For.

Expected result: all spoofed requests still return 429 — proxy ignores
X-Forwarded-For and always reads the real socket address.

Note: Only meaningful against the proxy (:4000). The backend (:3000) has no
IP blocking, so spoofing headers there has no effect to demonstrate.

Usage:
  python header_spoof.py http://localhost:4000/login
"""
import requests
import sys

TARGET     = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4000/login"
ACCOUNT    = "admin"
WORDLIST   = ["123456", "password", "admin", "qwerty", "letmein", "secret123"]
SPOOF_IPS  = [f"9.9.9.{i}" for i in range(1, 6)]

print(f"\n{'='*60}")
print(f"  HEADER SPOOFING ATTACK — target: {TARGET}")
print(f"{'='*60}\n")

# Step 1: trigger IP blacklist
print("Step 1 — Triggering IP blacklist via brute force...")
for pwd in WORDLIST:
    try:
        r = requests.post(TARGET, json={"username": ACCOUNT, "password": pwd}, timeout=10)
        print(f"  pass={pwd:<12}  status={r.status_code}")
        if r.status_code == 429:
            print("  >>> Real IP is now blacklisted.\n")
            break
    except requests.exceptions.ConnectionError:
        print(f"  Connection refused — is the server running at {TARGET}?")
        sys.exit(1)

# Step 2: attempt bypass via X-Forwarded-For
print("Step 2 — Attempting bypass with spoofed X-Forwarded-For headers...")
for ip in SPOOF_IPS:
    try:
        r = requests.post(
            TARGET,
            json={"username": ACCOUNT, "password": "bypass"},
            headers={"X-Forwarded-For": ip},
            timeout=10,
        )
        label = "BYPASSED" if r.status_code == 200 else "STILL BLOCKED"
        print(f"  X-Forwarded-For: {ip:<12}  status={r.status_code}  [{label}]")
    except requests.exceptions.ConnectionError:
        print(f"  Connection refused.")
        break

print()
print(">>> X-Forwarded-For is ignored — proxy always reads real socket IP.")
print()
