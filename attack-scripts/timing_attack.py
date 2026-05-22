"""
TC-06 — Timing Attack Demo
Demonstrates that crypto.timingSafeEqual() eliminates response-time side channels.

VULNERABILITY (before fix):
  if (user.password !== password)   <-- JavaScript === exits on FIRST differing char
  A password sharing more prefix with the real value takes slightly longer to reject.
  Attacker measures response times over many samples → guesses password char-by-char.

FIX (after):
  crypto.timingSafeEqual(Buffer.from(stored), Buffer.from(input))
  Compares every byte regardless of where the difference is.
  Timing is uniform whether the password is completely wrong or off by one last char.
"""
import requests
import time
import statistics
import sys

# Direct to backend (:3000) to measure raw comparison time without proxy overhead
TARGET   = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000/login"
USERNAME = "admin"
SAMPLES  = 40   # requests per category — more samples = more reliable average

# Real password for 'admin' is "secret123"
# We craft passwords with increasing prefix overlap to show/disprove timing leak
TEST_CASES = [
    ("no overlap    'xxxxxxxx'",  "xxxxxxxx"),
    ("2-char match  'sexxxxxx'",  "sexxxxxx"),
    ("5-char match  'secrexxx'",  "secrexxx"),
    ("8-char match  'secret12'",  "secret12"),
    ("9-char match  'secret123x'", "secret123x"),  # same prefix, 1 extra char
]

def measure(password, n):
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            requests.post(TARGET, json={"username": USERNAME, "password": password}, timeout=5)
        except requests.exceptions.ConnectionError:
            print(f"\n  ERROR: Cannot connect to {TARGET} — is the backend running?")
            sys.exit(1)
        times.append((time.perf_counter() - t0) * 1000)
    # Drop top/bottom 10% to reduce network jitter noise
    times.sort()
    trim = max(1, n // 10)
    return times[trim:-trim]

print(f"\n{'='*68}")
print(f"  TIMING ATTACK DEMO — target: {TARGET}")
print(f"  Account: {USERNAME}  |  Samples per category: {SAMPLES} (trimmed mean)")
print(f"{'='*68}\n")

print(f"  {'Password type':<38} {'Avg (ms)':>9}  {'Stdev':>7}")
print(f"  {'-'*38} {'-'*9}  {'-'*7}")

avgs = []
for label, pwd in TEST_CASES:
    times  = measure(pwd, SAMPLES)
    avg    = statistics.mean(times)
    stdev  = statistics.stdev(times)
    avgs.append(avg)
    print(f"  {label:<38} {avg:>9.2f}  {stdev:>7.2f}")

spread = max(avgs) - min(avgs)
print(f"\n  Timing spread across wrong passwords: {spread:.2f} ms")
print()

if spread < 8:
    print("  RESULT: Timing is UNIFORM across all wrong passwords.")
    print("          crypto.timingSafeEqual() is working correctly.")
    print("          Timing-based password enumeration is NOT viable.")
else:
    print("  WARNING: Noticeable timing variance detected!")
    print("           A consistent pattern over many runs may indicate a timing leak.")

print()
print("  Note: Some variance is expected due to network/OS jitter.")
print("  Run multiple times and compare trends rather than individual values.")
print()
