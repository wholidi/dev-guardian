"""
TC-01: Clean Baseline
Expected: No findings / zero critical issues
Purpose:  Establish false-positive rate for the scanner
"""

import hashlib
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def hash_password(password: str) -> str:
    """Securely hash a password using SHA-256 + salt."""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return salt.hex() + ":" + key.hex()


def get_user(user_id: int, db_cursor) -> dict:
    """Fetch user by ID using parameterised query."""
    db_cursor.execute("SELECT id, name, email FROM users WHERE id = %s", (user_id,))
    row = db_cursor.fetchone()
    if row:
        return {"id": row[0], "name": row[1], "email": row[2]}
    return {}


def render_greeting(name: str) -> str:
    """Return HTML-escaped greeting to prevent XSS."""
    import html
    safe_name = html.escape(name)
    return f"<p>Hello, {safe_name}!</p>"


if __name__ == "__main__":
    logger.info("Clean baseline module loaded — no vulnerabilities expected.")
