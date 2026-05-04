from pathlib import Path
import json
import os
import logging
from typing import List, Dict, Any, Tuple

from dotenv import load_dotenv
from openai import OpenAI
import httpx
import tiktoken

from .report_html import save_html_report

# ?????? Layer 3 Control 5: Token usage logger ???????????????????????????????????????????????????????????????????????????????????????????????????????????????
# Writes one line per agent call: timestamp, agent, model, prompt_tokens,
# completion_tokens, total_tokens, file scanned.
# Rotate or ship this file to your observability stack for Urielle billing.
_token_log = logging.getLogger("dev_guardian.token_usage")
if not _token_log.handlers:
    _handler = logging.FileHandler("token_usage.log")
    _handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    _token_log.addHandler(_handler)
    _token_log.setLevel(logging.INFO)


def _log_usage(agent: str, model: str, usage, label: str = "") -> None:
    """Extract and log token counts from an OpenAI response usage object."""
    if usage is None:
        return
    prompt     = getattr(usage, "input_tokens",  None) or getattr(usage, "prompt_tokens",     0)
    completion = getattr(usage, "output_tokens", None) or getattr(usage, "completion_tokens",  0)
    total      = (prompt or 0) + (completion or 0)
    _token_log.info(
        f"agent={agent} model={model} prompt={prompt} "
        f"completion={completion} total={total} label={label!r}"
    )
    print(
        f"[TokenUsage] ScanAgent | prompt={prompt} completion={completion} "
        f"total={total} | {label}"
    )

# ----------------------------------------------------------
# Load env
# ----------------------------------------------------------
load_dotenv()

# Lazy client ??? initialized on first use, not at import time
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


# ?????? Model config per agent role ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
# Blue team control: assign cheapest model that meets each agent's complexity.
# Switch SCAN_MODEL to "gpt-4.1" for production client scans.
#
# Tier 1 TPM limits (your account):
#   gpt-4.1       ??? 30,000 TPM   (high reasoning, use sparingly)
#   gpt-4.1-mini  ??? 200,000 TPM  (structured output, fast)
#   gpt-4.1-nano  ??? 200,000 TPM  (routing/classification only)

SCAN_MODEL       = "gpt-4.1-mini"   # ScanAgent: core vuln detection
CLASSIFY_MODEL   = "gpt-4.1-nano"   # RiskClassifierAgent: JSON normalisation only
SUMMARY_MODEL    = "gpt-4.1-mini"   # SummaryAgent: narrative (use gpt-4.1 for Executive mode)
SUPERVISOR_MODEL = "gpt-4.1-nano"   # SupervisorAgent: routing JSON only

# Legacy alias ??? kept so any external callers don't break
MODEL_NAME = SCAN_MODEL

INCLUDE_EXTENSIONS = {".py", ".js", ".ts", ".java", ".cs", ".go"}

# ?????? Layer 3 Control 1: max_output_tokens per agent ????????????????????????????????????????????????????????????????????????????????????
# Set as close to actual expected output as possible.
# Prevents runaway completions that inflate TPM and cost.
MAX_TOKENS_SCAN       = 5000   # ScanAgent: structured JSON findings
MAX_TOKENS_CLASSIFY   = 1500   # RiskClassifierAgent: JSON normalisation only (raised from 800 — Session 1 fix)
MAX_TOKENS_SUMMARY_TECH = 600  # SummaryAgent: technical mode (~300 words)
MAX_TOKENS_SUMMARY_EXEC = 1200 # SummaryAgent: executive mode (~600 words)
MAX_TOKENS_SUPERVISOR =  150   # SupervisorAgent: tiny routing JSON only

# ?????? Layer 3 Control 2: File size gates ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
# Enforced BEFORE any API call ??? zero token cost for oversized files.
MAX_SINGLE_FILE_BYTES  =  50_000   #  50 KB per individual source file
MAX_FOLDER_TOTAL_BYTES = 200_000   # 200 KB aggregate for folder/ZIP scans

# ?????? Layer 3 Control 3: Token budget per scan ??????????????????????????????????????????????????????????????????????????????????????????????????????
# tiktoken pre-flight: reject before the API call if input already too large.
# Protects your $10 monthly budget from a single runaway scan.
MAX_INPUT_TOKENS_PER_FILE = 8_000  # ~32KB of code; safe for gpt-4.1-mini context


def _estimate_tokens(text: str, model: str = "gpt-4o") -> int:
    """
    Estimate input token count using tiktoken before making the API call.
    Falls back to character-based estimate if encoding not found.
    """
    try:
        enc = tiktoken.encoding_for_model(model)
    except KeyError:
        enc = tiktoken.get_encoding("cl100k_base")  # safe fallback
    return len(enc.encode(text))


def _check_file_size(file_path: Path) -> None:
    """Raise ValueError if file exceeds single-file size gate."""
    size = file_path.stat().st_size
    if size > MAX_SINGLE_FILE_BYTES:
        raise ValueError(
            f"[SizeGate] {file_path.name} is {size:,} bytes "
            f"(limit {MAX_SINGLE_FILE_BYTES:,}). Skipping to protect token budget."
        )


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

=== LLM02: Sensitive Data Leakage to LLM / Logs ===
- Flag any logging (print, logger.*, log.*) of fields named: card, card_number, cvv, cvc,
  pan, credit_card, ssn, password, secret, token, api_key, private_key, or any field
  that looks like PII (email, phone, dob, national_id, passport).
- Flag any code that passes raw card numbers, CVV codes, or SSN values into an LLM
  prompt or API call without masking/tokenization. Severity: HIGH or CRITICAL.
- Flag any f-string or string concatenation that embeds PII into log output.

=== LLM09: Role Misrepresentation / Privilege Escalation ===
- Flag any system prompt or instruction string that assigns the LLM a privileged real-world
  identity it cannot verify: "You are a medical doctor", "You are a lawyer",
  "You are a licensed financial advisor", "You are a government official", etc.
- Flag if such a role assignment is missing a disclaimer stating the LLM is an AI assistant
  and not a licensed professional. Severity: HIGH.
- Flag any system prompt that instructs the LLM to override safety rules, claim special
  permissions, or ignore prior instructions (prompt injection enablers). Severity: CRITICAL.

=== LLM10: Unbounded Consumption / Resource Exhaustion ===
- Flag any LLM API call (openai.*, anthropic.*, responses.create, chat.completions.create,
  client.messages.create, etc.) that is missing a max_tokens / max_output_tokens parameter.
  Severity: MEDIUM. Recommendation: always set max_tokens to prevent runaway completions.
- Flag any endpoint or loop that invokes an LLM API without rate limiting or a request
  budget guard. Severity: MEDIUM.

=== LLM07: System Prompt Confidentiality ===
- Report each distinct system prompt secret or privileged instruction as a SEPARATE finding.
  Do NOT merge multiple system prompt issues into a single finding.
  Each sensitive instruction string exposed in code is its own finding with its own location.

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

CRITICAL FORMATTING RULE:
You MUST wrap ALL findings in a single JSON array [ ].
Even if there is only one finding, return [{"title": ...}].
Never return multiple separate objects. Always return one array.
"""

# Toggle this when your OpenAI quota is available again.
USE_REAL_LLM = True


# --------------------- single file ------------------------
def analyze_file(file_path: Path) -> List[Dict[str, Any]]:
    """
    Analyze a single file with the LLM.
    Layer 3 controls applied in order before any API call:
      1) File size gate       ??? rejects oversized files
      2) Token pre-flight     ??? rejects if input tokens exceed budget
      3) max_output_tokens    ??? hard cap on completion size
      4) JSON mode            ??? structured output only, no free-text bloat
      5) Token usage logging  ??? audit trail written to token_usage.log
    """
    if file_path.suffix.lower() not in {".py", ".js", ".ts", ".html", ".htm", ".txt", ".json", ".yaml", ".yml"}:
        return []

    # ?????? Control 2: File size gate ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    try:
        _check_file_size(file_path)
    except ValueError as e:
        print(str(e))
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

    # ?????? Control 3: Token pre-flight estimate ??????????????????????????????????????????????????????????????????????????????????????????????????????
    estimated_tokens = _estimate_tokens(text, model=SCAN_MODEL)
    print(f"[TokenPreflight] {file_path.name}: ~{estimated_tokens} input tokens estimated")
    if estimated_tokens > MAX_INPUT_TOKENS_PER_FILE:
        print(
            f"[TokenPreflight] REJECTED {file_path.name} ??? {estimated_tokens} tokens "
            f"exceeds budget of {MAX_INPUT_TOKENS_PER_FILE}. Truncating to limit."
        )
        # Truncate rather than hard-reject so partial analysis is still useful
        enc = tiktoken.get_encoding("cl100k_base")
        tokens = enc.encode(text)[:MAX_INPUT_TOKENS_PER_FILE]
        text = enc.decode(tokens)

    # ⚡ Control 4: Structured JSON output only
    # json_object mode requires "json" in the user message
    response = get_client().responses.create(
        model=SCAN_MODEL,
        instructions=SECURITY_INSTRUCTIONS,
        input=[{"role": "user", "content": "Return findings as a JSON array only.\n\n" + text}],
        max_output_tokens=MAX_TOKENS_SCAN,    # Control 1
        text={"format": {"type": "json_object"}},  # Control 4
    )

    # ?????? Control 5: Log token usage ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
    _log_usage("ScanAgent", SCAN_MODEL, getattr(response, "usage", None), file_path.name)

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

    # ?????? Control 2: Folder total size gate ???????????????????????????????????????????????????????????????????????????????????????????????????????????????
    target_files = [
        f for f in path.rglob("*")
        if f.is_file() and f.suffix.lower() in INCLUDE_EXTENSIONS
    ]
    total_bytes = sum(f.stat().st_size for f in target_files)
    print(f"[SizeGate] Folder total: {total_bytes:,} bytes across {len(target_files)} files")
    if total_bytes > MAX_FOLDER_TOTAL_BYTES:
        raise ValueError(
            f"[SizeGate] Folder scan rejected ??? {total_bytes:,} bytes total "
            f"exceeds limit of {MAX_FOLDER_TOTAL_BYTES:,}. "
            f"Zip only the src/ directory or split into smaller batches."
        )

    print(f"Analyzing folder recursively: {path}")
    all_findings: List[Dict[str, Any]] = []

    for file in target_files:
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





