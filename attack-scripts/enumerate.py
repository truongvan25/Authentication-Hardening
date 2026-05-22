"""
TC-03 — Account Enumeration Demo
Shows that the backend leaks which usernames exist via different error messages.
The proxy normalizes all 401 responses to the same generic body.
"""
import requests
import sys

BACKEND = "http://localhost:3000/login"
PROXY   = "http://localhost:4000/login"

TESTS = [
    ("ghost",  "x",         "non-existent user"),
    ("admin",  "wrongpass", "valid user, wrong password"),
    ("alice",  "x",         "valid user, wrong password"),
    ("nobody", "x",         "non-existent user"),
]

def probe(target_url, label):
    print(f"\n  --- {label} ---")
    bodies = []
    for username, password, note in TESTS:
        try:
            r = requests.post(target_url, json={"username": username, "password": password}, timeout=5)
            body_str = r.json().get("error", "")
            bodies.append(body_str)
            print(f"    username={username!r:10s}  ({note:35s})  -> {body_str!r}")
        except requests.exceptions.ConnectionError:
            print(f"    Connection refused — is {target_url} running?")
            return None
    return bodies

print(f"\n{'='*70}")
print("  ACCOUNT ENUMERATION TEST")
print(f"{'='*70}")

direct_bodies = probe(BACKEND, f"DIRECT to backend ({BACKEND})")
if direct_bodies:
    unique_direct = set(direct_bodies)
    if len(unique_direct) > 1:
        print(f"\n  RESULT (direct): {len(unique_direct)} DIFFERENT responses → username enumeration POSSIBLE")
    else:
        print(f"\n  RESULT (direct): responses identical")

proxy_bodies = probe(PROXY, f"THROUGH proxy ({PROXY})")
if proxy_bodies:
    unique_proxy = set(proxy_bodies)
    if len(unique_proxy) == 1:
        print(f"\n  RESULT (proxy):  ALL responses identical → enumeration PREVENTED")
    else:
        print(f"\n  RESULT (proxy):  {len(unique_proxy)} different responses — normalization not working!")
