"""
TC-04 — Distributed Brute Force Attack Demo
Simulates 12 different source IPs each sending one failed login attempt
against a single account. No single IP exceeds the rate limit threshold.

Run against :3000 to show no protection (all 12 succeed in reaching backend).
Run against :4000 to show account lockout triggers after 10 cumulative failures.

Usage:
  python distributed_brute.py http://localhost:4000/login   <- proxy (protected)
  python distributed_brute.py http://localhost:3000/login   <- backend (unprotected)
"""
import requests
import sys

TARGET  = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4000/login"
ACCOUNT = "admin"
IPS     = [f"10.0.0.{i}" for i in range(1, 13)]   # 12 simulated source IPs

print(f"\n{'='*60}")
print(f"  DISTRIBUTED BRUTE FORCE — target: {TARGET}")
print(f"  Account: {ACCOUNT}  |  Simulated IPs: {len(IPS)}")
print(f"  Each IP sends 1 request — IP rate limit never triggers")
print(f"{'='*60}\n")

for i, ip in enumerate(IPS, 1):
    password = f"wrong{i}"
    try:
        r = requests.post(
            TARGET,
            json={"username": ACCOUNT, "password": password},
            headers={"X-Real-IP": ip},
            timeout=10,
        )
        label = "LOCKED" if r.status_code == 423 else ("SUCCESS" if r.status_code == 200 else "fail")
        body  = r.json()
        print(f"IP {ip:<12}  pass={password:<10}  status={r.status_code}  [{label}]  {body.get('error', body.get('message', ''))}")
        if r.status_code == 423:
            print(f"\n>>> ACCOUNT LOCKED after {i} distributed failures — account lockout triggered.")
    except requests.exceptions.ConnectionError:
        print(f"IP {ip}: Connection refused — is the server running at {TARGET}?")
        break
    except requests.exceptions.Timeout:
        print(f"IP {ip}: Request timed out.")
        break

print()