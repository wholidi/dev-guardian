"""
TC-02: Hardcoded Secrets Detection
Expected: CRITICAL findings — API keys, passwords, tokens in source
Purpose:  Validate Dev Guardian's secret scanning capability
"""

import boto3
import anthropic
import requests

# ── INTENTIONAL TEST SECRETS (non-functional, for scanning only) ──────────────

AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"           # AWS IAM key pattern
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ANTHROPIC_API_KEY     = "sk-ant-api03-EXAMPLEKEYFORTESTINGONLY00000000000000000000"
STRIPE_SECRET_KEY     = "sk_live_EXAMPLESTRIPE0000000000000000000"
DATABASE_PASSWORD     = "Sup3rS3cr3tP@ssw0rd!"
JWT_SECRET            = "my-ultra-secure-jwt-secret-do-not-commit"
GITHUB_TOKEN          = "ghp_EXAMPLETOKEN000000000000000000000000"

# ── Functions that use the hardcoded values ────────────────────────────────────

def get_s3_client():
    """Connects to AWS using hardcoded credentials — NEVER do this."""
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name="ap-southeast-1",
    )


def call_anthropic():
    """Calls Anthropic API with hardcoded key — NEVER do this."""
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    return client.messages.create(
        model="claude-opus-4-6",
        max_tokens=10,
        messages=[{"role": "user", "content": "ping"}],
    )


def get_stripe_charge(amount: int):
    """Calls Stripe with hardcoded live key — NEVER do this."""
    headers = {"Authorization": f"Bearer {STRIPE_SECRET_KEY}"}
    return requests.post(
        "https://api.stripe.com/v1/charges",
        headers=headers,
        data={"amount": amount, "currency": "sgd"},
    )


def connect_db():
    """Returns connection string with embedded password — NEVER do this."""
    return f"postgresql://admin:{DATABASE_PASSWORD}@prod-db.internal:5432/appdb"


# ── Obfuscation variant: base64-encoded secret in comment ─────────────────────
# The following is a base64-encoded secret to test evasion detection:
# c2stbGl2ZS1FWEFNUEXFU1RSSVBFMDI=   <-- Stripe key, b64 encoded

ENCODED_TOKEN = "c2stbGl2ZS1FWEFNUEXFU1RSSVBFMDI="  # Should still be flagged
