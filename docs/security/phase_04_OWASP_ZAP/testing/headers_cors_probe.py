#!/usr/bin/env python3
"""
headers_cors_probe.py
Category : Security Headers / CORS Misconfiguration
Target   : https://dev-guardian-production.up.railway.app

Checks for:
  1. Missing or weak security response headers
  2. CORS misconfiguration (wildcard, reflection, credentialed wildcard)
  3. Information disclosure via Server / X-Powered-By headers
  4. Cookie security flags (Secure, HttpOnly, SameSite)

Usage:
    pip install requests
    python3 headers_cors_probe.py
"""

import requests

TARGET = "https://dev-guardian-production.up.railway.app"
ENDPOINTS = ["/ui", "/scan/file", "/scan/folder", "/health", "/docs"]

# ── Required Security Headers ────────────────────────────────────────────────

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "must_contain": "max-age",
        "desc": "HSTS — enforces HTTPS"
    },
    "Content-Security-Policy": {
        "required": True,
        "must_contain": None,
        "desc": "CSP — mitigates XSS"
    },
    "X-Content-Type-Options": {
        "required": True,
        "must_contain": "nosniff",
        "desc": "Prevents MIME sniffing"
    },
    "X-Frame-Options": {
        "required": True,
        "must_contain": None,
        "desc": "Clickjacking protection"
    },
    "Referrer-Policy": {
        "required": False,
        "must_contain": None,
        "desc": "Controls referrer leakage"
    },
    "Permissions-Policy": {
        "required": False,
        "must_contain": None,
        "desc": "Restricts browser features"
    },
    "Cache-Control": {
        "required": True,
        "must_contain": "no-store",
        "desc": "Prevents caching of sensitive reports"
    },
}

DANGEROUS_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                     "X-AspNetMvc-Version", "X-Generator"]

# ── CORS Test Origins ─────────────────────────────────────────────────────────

CORS_ORIGINS = [
    "https://attacker.invalid",
    "https://evil.dev-guardian-production.up.railway.app",  # subdomain
    "null",                                                   # null origin
    "https://localhost",
    "http://localhost:3000",
]

# ── Header Checks ─────────────────────────────────────────────────────────────

def check_security_headers(endpoint: str):
    url = TARGET + endpoint
    print(f"\n{'─'*60}")
    print(f"Endpoint: {url}")
    print(f"{'─'*60}")

    try:
        res = requests.get(url, timeout=10, allow_redirects=True)
    except Exception as e:
        print(f"  ERROR: {e}")
        return

    print(f"  HTTP {res.status_code}\n")

    # Required headers
    for header, config in REQUIRED_HEADERS.items():
        value = res.headers.get(header)
        if value is None:
            flag = "✗ MISSING" if config["required"] else "- ABSENT (recommended)"
            print(f"  {flag:30s} {header}")
            print(f"                                 ({config['desc']})")
        else:
            if config["must_contain"] and config["must_contain"] not in value.lower():
                print(f"  ⚠ WEAK VALUE               {header}: {value!r}")
            else:
                print(f"  ✓                          {header}: {value!r}")

    # Dangerous disclosure headers
    print()
    for header in DANGEROUS_HEADERS:
        value = res.headers.get(header)
        if value:
            print(f"  ✗ DISCLOSURE               {header}: {value!r}")

    # Cookie flags
    for cookie in res.cookies:
        flags = []
        if not cookie.secure:     flags.append("Missing Secure")
        if "HttpOnly" not in str(cookie): flags.append("Missing HttpOnly")
        if flags:
            print(f"  ✗ Cookie '{cookie.name}': {', '.join(flags)}")


# ── CORS Checks ───────────────────────────────────────────────────────────────

def check_cors():
    print(f"\n{'='*60}")
    print("CORS Configuration")
    print(f"{'='*60}")

    for origin in CORS_ORIGINS:
        headers = {"Origin": origin}
        try:
            res = requests.options(
                TARGET + "/scan/file",
                headers=headers,
                timeout=10
            )
            acao = res.headers.get("Access-Control-Allow-Origin", "")
            acac = res.headers.get("Access-Control-Allow-Credentials", "")
            acam = res.headers.get("Access-Control-Allow-Methods", "")

            print(f"\n  Origin   : {origin}")
            print(f"  ACAO     : {acao or '(not set)'}")
            print(f"  ACAC     : {acac or '(not set)'}")
            print(f"  Methods  : {acam or '(not set)'}")

            # Vulnerability checks
            if acao == "*" and acac.lower() == "true":
                print("  ✗ CRITICAL: Wildcard ACAO with credentials — CORS bypass!")
            elif acao == origin:
                print("  ✗ Origin reflected — verify if credentials are sent")
            elif acao == "*":
                print("  ⚠ Wildcard ACAO — public API acceptable if no auth")
            elif acao == "null":
                print("  ✗ null origin allowed — sandbox bypass possible")
            else:
                print("  ✓ No CORS misconfiguration detected for this origin")

        except Exception as e:
            print(f"\n  Origin {origin}: ERROR {e}")

# ── Information Disclosure via Error Pages ────────────────────────────────────

def check_error_disclosure():
    print(f"\n{'='*60}")
    print("Error Page Information Disclosure")
    print(f"{'='*60}")

    probes = [
        ("/nonexistent-path-12345", "404 path"),
        ("/scan/file",              "Empty POST (no file)"),
        ("/scan/folder",            "Empty POST (no ZIP)"),
    ]

    for path, desc in probes:
        url = TARGET + path
        try:
            if "scan" in path:
                res = requests.post(url, timeout=10)
            else:
                res = requests.get(url, timeout=10)

            body = res.text
            leak_indicators = [
                "Traceback", "stack trace", "Exception",
                "railway", "python", "langchain", "openai",
                "OPENAI_API_KEY", "AWS_", "SECRET",
            ]
            found = [i for i in leak_indicators if i.lower() in body.lower()]

            print(f"\n  {desc}: HTTP {res.status_code}")
            if found:
                print(f"  ✗ Disclosure indicators: {found}")
            else:
                print("  ✓ No stack traces or sensitive strings in error response")

        except Exception as e:
            print(f"\n  {desc}: ERROR {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Security Headers & CORS Probe")
    print(f"Target: {TARGET}\n")

    for endpoint in ENDPOINTS:
        check_security_headers(endpoint)

    check_cors()
    check_error_disclosure()

    print(f"\n{'='*60}")
    print("References:")
    print("  OWASP A05:2021 — Security Misconfiguration")
    print("  securityheaders.com for header grading")
    print("  OWASP CORS Cheat Sheet")
