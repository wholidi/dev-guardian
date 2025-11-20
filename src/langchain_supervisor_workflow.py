# langchain_supervisor_workflow.py
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain.agents import create_agent

# Your existing multi-agent workflow (already working)
from multi_agent_workflow import run_workflow_with_supervisor

# Load variables from .env (OPENAI_API_KEY, OPENAI_BASE_URL, etc.)
load_dotenv()

# Global so tools know which project they are scanning
CURRENT_PROJECT_PATH: Optional[Path] = None

# Use the same model name as your endpoint (adjust if needed)
MODEL_NAME = "o3-mini"


def _init_model():
    """
    Use the same Seagate OpenAI-compatible endpoint as ai_agent.py.
    Reads OPENAI_API_KEY (and optionally OPENAI_BASE_URL) from .env.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    base_url = os.getenv(
        "OPENAI_BASE_URL",
        "https://genai-models.seagate.com/openai/v1/",
    )

    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set – check your .env")

    return ChatOpenAI(
        model=MODEL_NAME,
        api_key=api_key,
        base_url=base_url,
    )


# --------------------------------------------------------------------
# 1) Low-level tool: call your existing multi-agent security workflow
# --------------------------------------------------------------------
@tool
def security_scan_project(request: str) -> str:
    """
    Run a full security scan on the CURRENT_PROJECT_PATH.

    Input:
        request: natural language instruction (e.g. 'do a full security scan')

    Output:
        A short natural-language summary of the key risks & issues.
    """
    if CURRENT_PROJECT_PATH is None:
        raise RuntimeError(
            "Project path not set. Make sure run_langchain_supervisor() "
            "sets CURRENT_PROJECT_PATH before invoking the agent."
        )

    # Reuse your existing (non-LangChain) multi-agent workflow
    result: Dict[str, Any] = run_workflow_with_supervisor(
        CURRENT_PROJECT_PATH,
        user_request=request or "Please perform a full security scan on this project.",
    )

    # --- Try to build a readable summary from your existing result structure ---
    # {
    #   "supervisor_decision": {...},
    #   "module_name": "security_scan",
    #   "result": {
    #       "summary": "Overall Risk Level: Critical ...",
    #       "findings": [ {title, severity, description, location}, ... ]
    #   }
    # }
    try:
        inner = result.get("result", {}) or {}
        summary_text = inner.get("summary") or ""
        findings = inner.get("findings") or []

        bullets = []
        for f in findings[:5]:
            title = f.get("title", "Issue")
            sev = f.get("severity", "?").upper()
            loc = f.get("location", "")
            bullets.append(f"- [{sev}] {title} ({loc})")

        if summary_text or bullets:
            return (
                f"{summary_text.strip()}\n\n"
                "Top issues from the scan:\n"
                + ("\n".join(bullets) if bullets else "No detailed findings available.")
            )

        # Fallback: no structured summary
        return "Security scan completed, but no structured summary was returned."

    except Exception:
        # Last-resort fallback: just dump the raw dict as text
        return "Security scan finished. Raw result:\n" + str(result)


# --------------------------------------------------------------------
# 2) Sub-agent: “Security Scan Agent” that uses the low-level tool
# --------------------------------------------------------------------
SECURITY_SCAN_AGENT_PROMPT = (
    "You are a security analysis specialist for Python / web backends.\n"
    "You receive natural language instructions (e.g. 'full scan', "
    "'focus on auth and secrets') and then call the 'security_scan_project' "
    "tool to actually scan the codebase at the current project path.\n\n"
    "After the tool finishes, you:\n"
    "- Explain the overall risk level and why.\n"
    "- Highlight the 3–5 most critical issues.\n"
    "- Suggest concrete next steps for the developer.\n"
    "Always respond clearly in markdown."
)

# Initialize model and security scan sub-agent
model = _init_model()

security_scan_agent = create_agent(
    model,
    tools=[security_scan_project],
    system_prompt=SECURITY_SCAN_AGENT_PROMPT,
)


# --------------------------------------------------------------------
# 3) Wrap the sub-agent as a tool for the supervisor
# --------------------------------------------------------------------
@tool
def perform_security_review(request: str) -> str:
    """
    High-level security review.

    The supervisor uses this when the user wants any kind of security analysis
    on the uploaded codebase (full scan, partial scan, focus on a module, etc.).
    """
    result = security_scan_agent.invoke(
        {"messages": [{"role": "user", "content": request}]}
    )

    # LangChain agents usually return {"messages": [...]}.
    messages = result.get("messages", [])
    if not messages:
        return str(result)

    last_msg = messages[-1]
    # Depending on LangChain version, .content or .text may exist
    if hasattr(last_msg, "content"):
        return last_msg.content
    if hasattr(last_msg, "text"):
        return last_msg.text
    return str(last_msg)


# --------------------------------------------------------------------
# 4) Supervisor agent: orchestrates high-level tools
# --------------------------------------------------------------------
SUPERVISOR_PROMPT = (
    "You are the SUPERVISOR for a GenAI Security Assistant.\n"
    "A user uploads a codebase (already mounted at a project path), "
    "then asks you to analyze its security posture.\n\n"
    "Your job:\n"
    "- Understand what the user wants (full scan, quick check, focus area, etc.).\n"
    "- Decide when to call 'perform_security_review'.\n"
    "- Combine tool output into a clear, human-readable report.\n"
    "- Be concise but specific, and prioritize HIGH/CRITICAL findings.\n"
    "If the user just asks 'what did you find?', summarize key issues.\n"
)

supervisor_agent = create_agent(
    model,
    tools=[perform_security_review],
    system_prompt=SUPERVISOR_PROMPT,
)


# --------------------------------------------------------------------
# 5) Public entrypoint used by your FastAPI endpoint
# --------------------------------------------------------------------
def run_langchain_supervisor(project_path: Path, user_request: str) -> Dict[str, Any]:
    """
    Entry point for the /api/upload-zip-langchain-supervisor endpoint.

    1. Set CURRENT_PROJECT_PATH so tools know which folder to scan.
    2. Ask the supervisor_agent to handle the user request.
    3. Return a simple dict with the final text report.
    """
    global CURRENT_PROJECT_PATH
    CURRENT_PROJECT_PATH = project_path

    result = supervisor_agent.invoke(
        {"messages": [{"role": "user", "content": user_request}]}
    )

    messages = result.get("messages", [])
    if messages:
        last_msg = messages[-1]
        if hasattr(last_msg, "content"):
            final_text = last_msg.content
        elif hasattr(last_msg, "text"):
            final_text = last_msg.text
        else:
            final_text = str(last_msg)
    else:
        final_text = str(result)

    return {
        "mode": "langchain_supervisor",
        "project_path": str(project_path),
        "user_request": user_request,
        "final_report": final_text,
    }
