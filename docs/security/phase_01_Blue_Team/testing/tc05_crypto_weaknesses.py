"""
TC-05: Unsafe Cryptography & Sensitive Data Exposure (OWASP A02, A04)
Expected: HIGH/CRITICAL — weak algorithms, no TLS, plaintext PII storage
Purpose:  Validate crypto and data-handling detection
"""

import hashlib
import base64
import json
import pickle
import ssl
import urllib.request


# ── WEAK HASHING ──────────────────────────────────────────────────────────────

def hash_password_md5(password: str) -> str:
    """VULNERABLE: MD5 is cryptographically broken for passwords."""
    return hashlib.md5(password.encode()).hexdigest()  # VULN


def hash_password_sha1(password: str) -> str:
    """VULNERABLE: SHA-1 is deprecated for password storage."""
    return hashlib.sha1(password.encode()).hexdigest()  # VULN


def store_token(token: str) -> str:
    """VULNERABLE: base64 is encoding, not encryption."""
    return base64.b64encode(token.encode()).decode()  # VULN — false sense of security


# ── PLAINTEXT SENSITIVE DATA ──────────────────────────────────────────────────

def save_user_pii(user: dict, filepath: str):
    """
    VULNERABLE: Writing PII (NRIC, DOB, salary) to plaintext JSON.
    No encryption, no masking, no access control.
    """
    pii_record = {
        "name": user["name"],
        "nric": user["nric"],           # Singapore NRIC — highly sensitive
        "dob": user["dob"],
        "salary": user["salary"],
        "bank_account": user["bank"],
    }
    with open(filepath, "w") as f:
        json.dump(pii_record, f)        # VULN — plaintext PII on disk


# ── INSECURE DESERIALISATION ──────────────────────────────────────────────────

def load_session(session_bytes: bytes) -> dict:
    """
    VULNERABLE: pickle.loads on untrusted input allows RCE.
    Payload: crafted pickle that executes os.system('id')
    """
    return pickle.loads(session_bytes)  # VULN — OWASP A08


# ── TLS / CERTIFICATE VERIFICATION DISABLED ──────────────────────────────────

def fetch_config(url: str) -> str:
    """VULNERABLE: SSL verification disabled — MITM possible."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False          # VULN
    ctx.verify_mode = ssl.CERT_NONE     # VULN
    with urllib.request.urlopen(url, context=ctx) as r:
        return r.read().decode()


def fetch_data_no_tls(endpoint: str) -> str:
    """VULNERABLE: Plain HTTP for sensitive API call."""
    url = f"http://{endpoint}/api/users"   # VULN — http not https
    with urllib.request.urlopen(url) as r:
        return r.read().decode()


# ── WEAK RANDOM FOR SECURITY CONTEXT ─────────────────────────────────────────

import random

def generate_session_token() -> str:
    """VULNERABLE: random is not cryptographically secure."""
    return str(random.randint(100000, 999999))   # VULN — use secrets.token_hex


def generate_reset_code() -> str:
    """VULNERABLE: predictable reset code."""
    random.seed(42)                              # VULN — fixed seed
    return "".join([str(random.randint(0, 9)) for _ in range(6)])
