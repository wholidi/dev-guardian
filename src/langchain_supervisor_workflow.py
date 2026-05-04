# langchain_supervisor_workflow.py
#
# LangGraph-based supervisor workflow for the Executive Report mode.
#
# Fixes vs original:
#   1. create_react_agent() from langgraph.prebuilt  (was: non-existent create_agent())
#   2. Lazy agent initialisation via _get_agents()   (was: module-level init that
#      crashed FastAPI startup when OPENAI_API_KEY was absent)
#   3. CURRENT_PROJECT_PATH uses threading.local()   (was: bare global — unsafe
#      under concurrent FastAPI requests)
#   4. MODEL_NAME updated to gpt-4.1-mini to match ai_agent.py model config

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.tools import tool

# LangGraph is the correct import for create_react_agent (not langchain.agents)
from langgraph.prebuilt import create_react_agent

from .multi_agent_workflow import run_workflow_with_supervisor

load_dotenv()

# ---------------------------------------------------------------------------
# Model config — mirrors SCAN_MODEL in ai_agent.py
# ---------------------------------------------------------------------------
MODEL_NAME = "gpt-4.1-mini"

# ---------------------------------------------------------------------------
# Thread-local project path
# ---------------------------------------------------------------------------
# Using threading.local() instead of a bare global means concurrent FastAPI
# requests each carry their own project path and cannot clobber each other.
_local = threading.local()


def _get_project_path() -> Optional[Path]:
    return getattr(_local, "project_path", None)


def _set_project_path(path: Path) -> None:
    _local.project_path = path


# ---------------------------------------------------------------------------
# Model factory — called lazily, not at import time
# ---------------------------------------------------------------------------
def _init_model() -> ChatOpenAI:
    """
    Build a ChatOpenAI client pointing at the configured endpoint.
    Reads OPENAI_API_KEY (and optionally OPENAI_BASE_URL) from the environment.
    Raises RuntimeError immediately with a clear message if the key is absent.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set — add it to Railway Variables or .env"
        )

    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

    return ChatOpenAI(
        model=MODEL_NAME,
        api_key=api_key,
        base_url=base_url,
    )


# ---------------------------------------------------------------------------
# Lazy agent cache — initialised once per process on first real request
# ---------------------------------------------------------------------------
_agents: Optional[Dict[str, Any]] = None
_agents_lock = threading.Lock()


def _get_agents() -> Dict[str, Any]:
    """
    Return (and lazily create) the compiled supervisor + sub-agent graphs.
    Thread-safe: uses a lock so concurrent first-requests don't double-init.
    """
    global _agents
    if _agents is not None:
        return _agents

    with _agents_lock:
        # Double-checked locking — another thread may have initialised while
        # we were waiting for the lock.
        if _agents is not None:
            return _agents

        model = _init_model()

        # ── Sub-agent: Security Scan ─────────────────────────────────────
        _SCAN_AGENT_PROMPT = (
            "You are a security analysis specialist for Python / web backends.\n"
            "You receive natural language instructions (e.g. 'full scan', "
            "'focus on auth and secrets') and call the 'security_scan_project' "
            "tool to scan the codebase at the current project path.\n\n"
            "After the tool finishes you:\n"
            "- Explain the overall risk level and why.\n"
            "- Highlight the 3-5 most critical issues.\n"
            "- Suggest concrete next steps for the developer.\n"
            "Always respond clearly in markdown."
        )

        security_scan_agent = create_react_agent(
            model,
            tools=[security_scan_project],
            prompt=_SCAN_AGENT_PROMPT,
        )

        # ── Supervisor agent ─────────────────────────────────────────────
        _SUPERVISOR_PROMPT = (
            "You are the SUPERVISOR for a GenAI Security Assistant.\n"
            "A user uploads a codebase (mounted at a project path) then asks "
            "you to analyse its security posture.\n\n"
            "Your job:\n"
            "- Understand what the user wants (full scan, quick check, focus area).\n"
            "- Decide when to call 'perform_security_review'.\n"
            "- Combine tool output into a clear, human-readable report.\n"
            "- Be concise but specific; prioritise HIGH/CRITICAL findings.\n"
            "If the user asks 'what did you find?', summarise key issues."
        )

        supervisor_agent = create_react_agent(
            model,
            tools=[perform_security_review],
            prompt=_SUPERVISOR_PROMPT,
        )

        _agents = {
            "security_scan_agent": security_scan_agent,
            "supervisor_agent": supervisor_agent,
        }
        return _agents


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@tool
def security_scan_project(request: str) -> str:
    """
    Run a full security scan on the current project path.

    Args:
        request: natural language instruction
                 (e.g. 'do a full security scan', 'focus on auth issues')

    Returns:
        Plain-text summary of key risks and top findings.
    """
    project_path = _get_project_path()
    if project_path is None:
        raise RuntimeError(
            "Project path not set. "
            "Ensure run_langchain_supervisor() is called before the agent."
        )

    result: Dict[str, Any] = run_workflow_with_supervisor(
        project_path,
        user_request=request or "Please perform a full security scan on this project.",
    )

    # Build a readable summary from the structured result
    # Expected shape:
    # {
    #   "supervisor_decision": {...},
    #   "module_name": "security_scan",
    #   "result": {
    #       "summary": "Overall Risk Level: Critical ...",
    #       "findings": [ {title, severity, description, location}, ... ]
    #   }
    # }
    try:
        inner   = result.get("result", {}) or {}
        summary = (inner.get("summary") or "").strip()
        findings = inner.get("findings") or []

        bullets = [
            f"- [{f.get('severity', '?').upper()}] {f.get('title', 'Issue')} "
            f"({f.get('location', '')})"
            for f in findings[:5]
        ]

        if summary or bullets:
            return (
                f"{summary}\n\n"
                "Top issues from the scan:\n"
                + ("\n".join(bullets) if bullets else "No detailed findings available.")
            )

        return "Security scan completed, but no structured summary was returned."

    except Exception:
        return "Security scan finished. Raw result:\n" + str(result)


@tool
def perform_security_review(request: str) -> str:
    """
    High-level security review tool used by the supervisor agent.

    The supervisor calls this when the user wants any security analysis
    on the uploaded codebase (full scan, partial scan, module focus, etc.).

    Args:
        request: natural language description of what to analyse

    Returns:
        Markdown-formatted security review from the sub-agent.
    """
    agents = _get_agents()
    security_scan_agent = agents["security_scan_agent"]

    result = security_scan_agent.invoke(
        {"messages": [{"role": "user", "content": request}]}
    )

    messages = result.get("messages", [])
    if not messages:
        return str(result)

    last = messages[-1]
    if hasattr(last, "content"):
        return last.content
    if hasattr(last, "text"):
        return last.text
    return str(last)


# ---------------------------------------------------------------------------
# Public entrypoint — called by FastAPI /scan (executive mode) and /lc-supervisor-zip
# ---------------------------------------------------------------------------

def run_langchain_supervisor(
    project_path: Path,
    user_request: str,
) -> Dict[str, Any]:
    """
    Entry point for LangGraph-powered executive report generation.

    1. Stores project_path in thread-local storage.
    2. Lazily initialises the supervisor + sub-agent graphs on first call.
    3. Invokes the supervisor with the user's request.
    4. Returns a plain dict with the final report text.

    Args:
        project_path: absolute path to the extracted project directory
        user_request: natural language instruction from the user

    Returns:
        {
            "mode":         "langchain_supervisor",
            "project_path": str,
            "user_request": str,
            "final_report": str   # markdown narrative
        }
    """
    # Store path in thread-local so the @tool functions can read it safely
    _set_project_path(project_path)

    agents = _get_agents()
    supervisor = agents["supervisor_agent"]

    result = supervisor.invoke(
        {"messages": [{"role": "user", "content": user_request}]}
    )

    messages = result.get("messages", [])
    if messages:
        last = messages[-1]
        if hasattr(last, "content"):
            final_text = last.content
        elif hasattr(last, "text"):
            final_text = last.text
        else:
            final_text = str(last)
    else:
        final_text = str(result)

    return {
        "mode":         "langchain_supervisor",
        "project_path": str(project_path),
        "user_request": user_request,
        "final_report": final_text,
    }
