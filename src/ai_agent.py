from pathlib import Path
import json
import os
from typing import List, Dict, Any

from dotenv import load_dotenv
from openai import OpenAI
import httpx

from .report_html import save_html_report

# ----------------------------------------------------------
# Load env
# ----------------------------------------------------------
load_dotenv()

# Lazy client — initialized on first use, not at import time
_http_client = httpx.Client(timeout=60.0)
_client = None


def get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Add it to Railway Variables."
            )
        _client = OpenAI(
            base_url="https://api.openai.com/v1",
            api_key=api_key,
            http_client=_http_client,
        )
    return _client


MODEL_NAME = "o3-mini"
INCLUDE_EXTENSIONS = {".py", ".js", ".ts", ".java", ".cs", ".go"}


SECURITY_INSTRUCTIONS = """
You are a senior application security engineer performing a STRICT security review.

The code you receive MAY contain vulnerabilities. You MUST actively look for issues, especially:

- SQL, NoSQL, command or LDAP injection
- XSS / HTML injection
- Authentication and authorization weaknesses
- Hardcoded secrets / credentials / tokens
- Insecure cryptography and random number generation
- Insecure file handling, deserialization, or use of eval/exec
- Logging or exposing sensitive data
- Any other OWASP-style vulnerability

Rules:
- Treat ALL external / user input as UNTRUSTED by default.
- If untrusted data is concatenated into a SQL query string,
  this MUST be flagged as HIGH severity SQL Injection.
- If ANY possible vulnerability exists, you MUST report it.
- Only return [] if the code is genuinely safe.

Output format:
Return ONLY a JSON array. Each element MUST be an object with:
- title
- severity ("low", "medium", "high", "critical")
- location
- description
- recommendation
"""

# Toggle this when your OpenAI quota is available again.
USE_REAL_LLM = False


# --------------------- single file ------------------------
def analyze_file(file_path: Path) -> List[Dict[str, Any]]:
    """
    Analyze a single file with the LLM.
    Tries to salvage as many valid finding objects as possible from imperfect JSON.
    """
    if file_path.suffix.lower() not in {".py", ".js", ".ts", ".html", ".htm", ".txt", ".json", ".yaml", ".yml"}:
        return []

    try:
        text = file_path.read_text(errors="ignore")
    except Exception as e:
        print(f"[ScanAgent] Could not read {file_path}: {e}")
        return []

    if not text.strip():
        return []

    print(f"\n--- Analyzing {file_path} ---\n")

    if not USE_REAL_LLM:
        print("[MockMode] Skipping OpenAI call due to quota limit.")
        return [
            {
                "title": "Demo Finding",
                "severity": "low",
                "location": str(file_path),
                "description": "This is a simulated result for demo purposes.",
                "recommendation": "Replace mock mode with real analysis when API quota is available.",
                "source_file": str(file_path),
            }
        ]

    response = get_client().responses.create(
        model=MODEL_NAME,
        instructions=SECURITY_INSTRUCTIONS,
        input=[{"role": "user", "content": text}],
        max_output_tokens=1500,
    )

    raw_text = (response.output_text or "").strip()
    print(f"\nRAW MODEL OUTPUT for {file_path}:\n{raw_text}\n")

    if raw_text == "" or raw_text == "[]":
        return []

    start = raw_text.find("[")
    end = raw_text.rfind("]")
    candidate = raw_text[start : end + 1] if start != -1 and end != -1 else raw_text

    findings: List[Dict[str, Any]] = []

    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            parsed = [parsed]
        if isinstance(parsed, list):
            findings = parsed
    except Exception:
        import re

        print(f"[ScanAgent] Bulk JSON parse failed for {file_path}, trying object-by-object.")
        obj_pattern = re.compile(r"\{.*?\}", re.DOTALL)
        objs: List[Dict[str, Any]] = []

        for match in obj_pattern.finditer(candidate):
            obj_text = match.group()
            try:
                obj = json.loads(obj_text)
                if isinstance(obj, dict):
                    objs.append(obj)
            except Exception:
                continue

        findings = objs

    if not findings:
        print(f"[ScanAgent] No valid finding objects parsed for {file_path}.")
        return []

    for f in findings:
        f.setdefault("source_file", str(file_path))

    print(f"[ScanAgent] Parsed {len(findings)} findings from {file_path}.")
    return findings


# --------------------- file OR folder ---------------------
def analyze_path(path: Path) -> List[Dict[str, Any]]:
    if path.is_file():
        print(f"Analyzing single file: {path}")
        return analyze_file(path)

    if not path.is_dir():
        raise FileNotFoundError(f"Path not found: {path}")

    print(f"Analyzing folder recursively: {path}")
    all_findings: List[Dict[str, Any]] = []

    for file in path.rglob("*"):
        if not file.is_file():
            continue
        if file.suffix.lower() not in INCLUDE_EXTENSIONS:
            continue
        print(f"\n--- Analyzing {file} ---")
        try:
            file_findings = analyze_file(file)
            all_findings.extend(file_findings)
        except Exception as e:
            print(f"ERROR analyzing {file}: {e}")

    return all_findings


# -------------------------- CLI ---------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="GenAI Security Code Review (file or folder)"
    )
    parser.add_argument(
        "target",
        help="File or folder path to analyze (e.g. app.py or 'File Scanner' or Src)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Optional JSON output path for findings (e.g. findings.json)",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Also generate an HTML report (security_report.html by default).",
    )
    parser.add_argument(
        "--html-path",
        help="Custom path for HTML report (default: security_report.html)",
    )

    args = parser.parse_args()
    target_path = Path(args.target).resolve()

    results = analyze_path(target_path)

    print("\nFINAL FINDINGS:\n")
    print(json.dumps(results, indent=2, ensure_ascii=False))

    if args.output:
        out_path = Path(args.output).resolve()
        out_path.write_text(
            json.dumps(results, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"\nSaved findings JSON to {out_path}")

    if args.html:
        html_path = (
            Path(args.html_path).resolve()
            if args.html_path
            else Path("security_report.html").resolve()
        )
        save_html_report(results, html_path)
        print(f"Saved HTML report to {html_path}")
