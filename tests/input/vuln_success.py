# vuln_success.py
import sqlite3
from flask import request

def get_user():
    conn = sqlite3.connect("users.db")
    username = request.args.get("username")  # untrusted input
    query = f"SELECT * FROM users WHERE name = '{username}'"  # SQL injection
    return conn.execute(query).fetchall()
