# multi_agent_workflow.py

from pathlib import Path
from typing import List, Dict, Any, Callable
import json
import time

from .ai_agent import (
    analyze_path, get_client,
    SCAN_MODEL, CLASSIFY_MODEL, SUMMARY_MODEL, SUPERVISOR_MODEL,
    MAX_TOKENS_CLASSIFY, MAX_TOKENS_SUMMARY_TECH, MAX_TOKENS_SUMMARY_EXEC,
    MAX_TOKENS_SUPERVISOR,
    _log_usage,
)

# Guardrails is optional ??? app works without it
try:
    from .guardrails_utils import guard_findings
    GUARDRAILS_AVAILABLE = True
except ImportError:
    guard_findings = None
    GUARDRAILS_AVAILABLE = False

# ---------- Agent 1: ScanAgent ----------

SCAN_AGENT_NAME = "ScanAgent"
SCAN_AGENT_ROLE = "LLM-powered codebase security scanner"

def scan_agent(project_path: Path) -> List[Dict[str, Any]]:
    print(f"[{SCAN_AGENT_NAME}] Starting scan of: {project_path}")
    findings = analyze_path(project_path)
    print(f"[{SCAN_AGENT_NAME}] Finished scan. Total findings: {len(findings)}")
    return findings


# ---------- Agent 2: RiskClassifierAgent ----------

RISK_AGENT_NAME = "RiskClassifierAgent"
RISK_AGENT_ROLE = "Security triage specialist (severity & OWASP mapping)"

RISK_CLASSIFIER_PROMPT = """
You are a security triage expert.

You will receive a JSON array of security findings from another agent.
Each finding has: title, severity, location, description, recommendation, source_file.

Tasks:
1. Normalize `severity` into one of: low, medium, high, critical.
2. (Optional) Add `owasp_category` if you can map it (e.g., A01: Broken Access Control).
3. Do NOT remove any finding. Only enrich or normalize.

=== LLM07 Rule — System Prompt Confidentiality ===
Each distinct system prompt issue must remain as a SEPARATE finding.
Do NOT merge multiple system prompt findings into one, even if they are in the same file.

Return ONLY a JSON array of findings with the same fields plus optional `owasp_category`.
"""

def risk_classifier_agent(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not findings:
        print(f"[{RISK_AGENT_NAME}] No findings to classify.")
        return []

    print(f"[{RISK_AGENT_NAME}] Classifying {len(findings)} findings.")
    response = get_client().responses.create(
        model=CLASSIFY_MODEL,
        instructions=RISK_CLASSIFIER_PROMPT,
        input=[{"role": "user", "content": "Return a JSON array of enriched findings.\n\n" + json.dumps(findings, ensure_ascii=False)}],
        max_output_tokens=MAX_TOKENS_CLASSIFY,              # Control 1
        text={"format": {"type": "json_object"}},           # Control 4
    )

    # Control 5: log token usage
    _log_usage(RISK_AGENT_NAME, CLASSIFY_MODEL, getattr(response, "usage", None), f"{len(findings)} findings")

    raw = (response.output_text or "").strip()

    # --- 1) Guardrails schema enforcement + repair (optional) ---
    if GUARDRAILS_AVAILABLE and guard_findings is not None:
        try:
            # Parse raw JSON first, then validate through Pydantic guard
            start = raw.find("[")
            end = raw.rfind("]")
            candidate = raw[start : end + 1] if start != -1 and end != -1 else raw
            pre_parsed = json.loads(candidate)
            if isinstance(pre_parsed, dict):
                pre_parsed = [pre_parsed]
            classified = guard_findings(pre_parsed)   # accepts list → normalises + validates
            print(f"[{RISK_AGENT_NAME}] Classification complete via Guardrails.")
            return classified
        except Exception as e:
            print(f"[{RISK_AGENT_NAME}] Guardrails error, falling back. {e}")

    # --- 2) Fallback: your original JSON parsing ---
    try:
        start = raw.find("[")
        end = raw.rfind("]")
        candidate = raw[start : end + 1] if start != -1 and end != -1 else raw
        enriched = json.loads(candidate)
        if isinstance(enriched, dict):
            enriched = [enriched]
        if isinstance(enriched, list):
            print(f"[{RISK_AGENT_NAME}] Classification complete (fallback parser).")
            return enriched
    except Exception as e:
        print(f"[{RISK_AGENT_NAME}] ERROR parsing LLM output, returning original findings. {e}")

    return findings

# ---------- Agent 3: SummaryAgent ----------

SUMMARY_AGENT_NAME = "SummaryAgent"
SUMMARY_AGENT_ROLE = "Security architect producing executive summary"

SUMMARY_PROMPT = """
You are a senior security architect. Create a concise summary of the findings.

Include:
- Overall risk level (low/medium/high/critical) for the project
- 3???5 key issues to fix first
- Any quick wins or hardening recommendations

Return plain text, max ~300 words.
"""

def summary_agent(findings: List[Dict[str, Any]], executive_mode: bool = False) -> str:
    if not findings:
        print(f"[{SUMMARY_AGENT_NAME}] No findings, returning clean summary.")
        return "No security issues were detected in the analyzed codebase."

    max_tok = MAX_TOKENS_SUMMARY_EXEC if executive_mode else MAX_TOKENS_SUMMARY_TECH
    mode_label = "executive" if executive_mode else "technical"

    print(f"[{SUMMARY_AGENT_NAME}] Creating {mode_label} summary (max_tokens={max_tok}).")
    response = get_client().responses.create(
        model=SUMMARY_MODEL,
        instructions=SUMMARY_PROMPT,
        input=[{"role": "user", "content": "Return a JSON array of enriched findings.\n\n" + json.dumps(findings, ensure_ascii=False)}],
        max_output_tokens=max_tok,    # Control 1 ??? flex by mode
    )

    # Control 5: log token usage
    _log_usage(SUMMARY_AGENT_NAME, SUMMARY_MODEL, getattr(response, "usage", None), mode_label)

    return (response.output_text or "").strip()

# ---------- SupervisorAgent: routes to workflows ----------

SUPERVISOR_AGENT_NAME = "SupervisorAgent"
SUPERVISOR_AGENT_ROLE = "Routes user requests to the correct module/workflow"

SUPERVISOR_PROMPT = """
You are an orchestration supervisor for an AI security platform.

You must select EXACTLY ONE module for the user's request.

Available modules:
- security_scan: Scan codebase for security issues (current implementation)
- rag_assistant: RAG-style Q&A over project docs (not implemented yet)
- sql_explorer: Help explore structured data / logs via SQL (not implemented yet)
- python_toolkit: Run Python utilities or small scripts (not implemented yet)

Return ONLY a compact JSON object:
{
  "selected_module": "<one of: security_scan, rag_assistant, sql_explorer, python_toolkit>",
  "reason": "<short one-line explanation>"
}
"""

def supervisor_agent(user_request: str) -> Dict[str, Any]:
    print(f"[{SUPERVISOR_AGENT_NAME}] Routing request: {user_request!r}")

    response = get_client().responses.create(
        model=SUPERVISOR_MODEL,
        instructions=SUPERVISOR_PROMPT,
        input=[{"role": "user", "content": "Return a JSON object with your routing decision.\n\n" + user_request}],
        max_output_tokens=MAX_TOKENS_SUPERVISOR,            # Control 1
        text={"format": {"type": "json_object"}},           # Control 4
    )

    # Control 5: log token usage
    _log_usage(SUPERVISOR_AGENT_NAME, SUPERVISOR_MODEL, getattr(response, "usage", None), "routing")

    raw = (response.output_text or "").strip()
    try:
        decision = json.loads(raw)
        if not isinstance(decision, dict):
            raise ValueError("Supervisor output is not a JSON object")
    except Exception as e:
        print(f"[{SUPERVISOR_AGENT_NAME}] Parse error, defaulting to security_scan. {e}")
        decision = {
            "selected_module": "security_scan",
            "reason": "Fallback to default security scan due to parsing error.",
        }

    # safety net
    if decision.get("selected_module") not in {
        "security_scan", "rag_assistant", "sql_explorer", "python_toolkit"
    }:
        decision["selected_module"] = "security_scan"
        decision["reason"] = (
            "Invalid module name from model; defaulted to security_scan."
        )

    print(f"[{SUPERVISOR_AGENT_NAME}] Decision: {decision}")
    return decision

# ---------- Coordinator: orchestrate all agents ----------

def security_scan_workflow(project_path: Path, executive_mode: bool = False) -> Dict[str, Any]:
    """
    Security scan workflow:
      1) ScanAgent           -> raw findings
      2) RiskClassifierAgent -> normalized/enriched findings
      3) SummaryAgent        -> human-readable summary

    Args:
        executive_mode: If True, SummaryAgent uses higher token cap and
                        narrative style. If False, technical concise output.
    """

    workflow_trace: List[Dict[str, Any]] = []

    # 1) ScanAgent
    t0 = time.time()
    raw_findings = scan_agent(project_path)
    t1 = time.time()
    workflow_trace.append({
        "agent": SCAN_AGENT_NAME,
        "role": SCAN_AGENT_ROLE,
        "duration_sec": round(t1 - t0, 2),
        "total_findings": len(raw_findings),
    })

    # 2) RiskClassifierAgent
    t2 = time.time()
    classified_findings = risk_classifier_agent(raw_findings)
    t3 = time.time()
    workflow_trace.append({
        "agent": RISK_AGENT_NAME,
        "role": RISK_AGENT_ROLE,
        "duration_sec": round(t3 - t2, 2),
        "total_findings": len(classified_findings),
    })

    # 3) SummaryAgent ??? executive_mode controls token budget
    t4 = time.time()
    summary = summary_agent(classified_findings, executive_mode=executive_mode)
    t5 = time.time()
    workflow_trace.append({
        "agent": SUMMARY_AGENT_NAME,
        "role": SUMMARY_AGENT_ROLE,
        "duration_sec": round(t5 - t4, 2),
        "total_findings": len(classified_findings),
    })

    return {
        "summary": summary,
        "findings": classified_findings,
        "workflow_trace": workflow_trace,
    }


# registry for future modules
WORKFLOWS: Dict[str, Callable[[Path], Dict[str, Any]]] = {
    "security_scan": security_scan_workflow,
    # future:
    # "rag_assistant": rag_assistant_workflow,
    # "sql_explorer": sql_explorer_workflow,
    # "python_toolkit": python_toolkit_workflow,
}


def run_multi_agent_workflow(project_path: Path) -> Dict[str, Any]:
    """
    Backwards-compatible entrypoint: just run the security_scan workflow.
    """
    return security_scan_workflow(project_path)

def run_workflow_with_supervisor(project_path: Path, user_request: str) -> Dict[str, Any]:
    """
    Full Concept Module:
      - SupervisorAgent     -> chooses which module to invoke
      - Selected workflow   -> e.g. security_scan_workflow
    """
    decision = supervisor_agent(user_request)
    module_name = decision.get("selected_module", "security_scan")

    workflow = WORKFLOWS.get(module_name, security_scan_workflow)

    result = workflow(project_path)
    return {
        "supervisor_decision": decision,
        "module_name": module_name,
        "result": result,
    }


