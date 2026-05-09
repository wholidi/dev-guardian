#!/usr/bin/env python3
"""
dos_probe.py
Category : Denial of Service / Resource Exhaustion
Target   : /scan/file and /scan/folder

Tests whether the app enforces:
  1. File size limits  (expect 413 Request Entity Too Large)
  2. Request rate limiting (expect 429 Too Many Requests)
  3. Processing timeouts (expect 408 or 504, not indefinite hang)
  4. Concurrent request handling (connection pool exhaustion)

Usage:
    pip install requests
    python3 dos_probe.py

NOTE: Run against DEV environment only. Do NOT run concurrency test
      at high thread counts against a shared/production host.
"""

import io
import time
import threading
import requests

TARGET = "https://dev-guardian-production.up.railway.app"
FILE_ENDPOINT   = f"{TARGET}/scan/file"
FOLDER_ENDPOINT = f"{TARGET}/scan/folder"
TIMEOUT_SECONDS = 30

# ── Test 1: File Size Limits ─────────────────────────────────────────────────

FILE_SIZES = [
    ("1 MB",    1   * 1024 * 1024),
    ("10 MB",   10  * 1024 * 1024),
    ("50 MB",   50  * 1024 * 1024),
    ("100 MB", 100  * 1024 * 1024),
]

def test_file_size_limits():
    print("=" * 60)
    print("TEST 1: File Size Limits")
    print("=" * 60)
    for label, size in FILE_SIZES:
        payload = b"A" * size
        files   = {"file": ("huge_file.py", io.BytesIO(payload), "text/x-python")}
        try:
            t0  = time.time()
            res = requests.post(FILE_ENDPOINT, files=files, timeout=TIMEOUT_SECONDS)
            elapsed = time.time() - t0
            status  = res.status_code
            flag    = "✓ REJECTED" if status in (413, 400) else "✗ ACCEPTED — potential DoS"
            print(f"  {label:8s} → HTTP {status} ({elapsed:.1f}s)  {flag}")
        except requests.exceptions.Timeout:
            print(f"  {label:8s} → TIMEOUT ({TIMEOUT_SECONDS}s) — no size limit enforced")
        except Exception as e:
            print(f"  {label:8s} → ERROR: {e}")
    print()

# ── Test 2: Rate Limiting ────────────────────────────────────────────────────

RATE_LIMIT_REQUESTS = 20
RATE_LIMIT_WINDOW   = 10  # seconds

def test_rate_limiting():
    print("=" * 60)
    print("TEST 2: Rate Limiting")
    print(f"  Sending {RATE_LIMIT_REQUESTS} requests in {RATE_LIMIT_WINDOW}s")
    print("=" * 60)
    tiny_file = b"print('hello')"
    start     = time.time()
    statuses  = []

    for i in range(RATE_LIMIT_REQUESTS):
        files = {"file": ("test.py", io.BytesIO(tiny_file), "text/x-python")}
        try:
            res = requests.post(FILE_ENDPOINT, files=files, timeout=10)
            statuses.append(res.status_code)
            print(f"  Request {i+1:02d}: HTTP {res.status_code}")
        except Exception as e:
            print(f"  Request {i+1:02d}: ERROR {e}")
            statuses.append(0)

    elapsed = time.time() - start
    rate_limited = statuses.count(429)
    print(f"\n  Completed {RATE_LIMIT_REQUESTS} requests in {elapsed:.1f}s")
    print(f"  429 responses: {rate_limited}")
    if rate_limited == 0:
        print("  ✗ No rate limiting detected")
    else:
        print("  ✓ Rate limiting active")
    print()

# ── Test 3: Processing Timeout (CPU-intensive payload) ───────────────────────

def test_processing_timeout():
    print("=" * 60)
    print("TEST 3: Processing Timeout")
    print("  Upload a CPU-intensive file; server should timeout gracefully")
    print("=" * 60)

    # A deeply nested structure that may cause O(n^2) analysis time
    bomb_content = "class A" + "".join(
        f"\n  class B{i}:\n    pass" for i in range(500)
    )
    bomb_content += "\n" + "x = " + "(" * 500 + "1" + ")" * 500

    files = {"file": ("cpu_bomb.py", io.BytesIO(bomb_content.encode()), "text/x-python")}
    try:
        t0  = time.time()
        res = requests.post(FILE_ENDPOINT, files=files, timeout=120)
        elapsed = time.time() - t0
        print(f"  HTTP {res.status_code} after {elapsed:.1f}s")
        if elapsed > 60:
            print("  ✗ No processing timeout — potential CPU exhaustion")
        else:
            print("  ✓ Responded within acceptable time")
    except requests.exceptions.Timeout:
        print("  ✗ Client-side timeout hit — server may have no timeout limit")
    print()

# ── Test 4: Concurrent Request Flood ────────────────────────────────────────

CONCURRENT_THREADS = 10  # Keep low for dev environment

def single_request(thread_id, results):
    tiny = b"print('concurrent test')"
    files = {"file": (f"test_{thread_id}.py", io.BytesIO(tiny), "text/x-python")}
    try:
        t0  = time.time()
        res = requests.post(FILE_ENDPOINT, files=files, timeout=30)
        results.append((thread_id, res.status_code, time.time() - t0))
    except Exception as e:
        results.append((thread_id, 0, -1))

def test_concurrent_requests():
    print("=" * 60)
    print(f"TEST 4: Concurrent Requests ({CONCURRENT_THREADS} threads)")
    print("=" * 60)
    results = []
    threads = [
        threading.Thread(target=single_request, args=(i, results))
        for i in range(CONCURRENT_THREADS)
    ]
    t0 = time.time()
    for t in threads: t.start()
    for t in threads: t.join()
    elapsed = time.time() - t0

    print(f"  All {CONCURRENT_THREADS} requests completed in {elapsed:.1f}s")
    for tid, status, dur in sorted(results):
        flag = "✓" if status == 200 else ("⚠ 429" if status == 429 else f"✗ {status}")
        print(f"  Thread {tid:02d}: HTTP {status} ({dur:.1f}s) {flag}")
    errors = sum(1 for _, s, _ in results if s not in (200, 429))
    if errors:
        print(f"\n  ✗ {errors} errors under concurrent load — possible resource exhaustion")
    else:
        print("\n  ✓ Concurrent load handled without errors")

# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\nDoS Probe: dev-guardian-production.up.railway.app")
    print("Environment: DEV — safe to run\n")
    test_file_size_limits()
    test_rate_limiting()
    test_processing_timeout()
    test_concurrent_requests()
    print("\nDone. Review findings above against OWASP API4:2023 (Unrestricted Resource Consumption)")
