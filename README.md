# Dev Guardian 
It is a GenAI-powered Security Agent — an intelligent, automated code-review system designed to help teams quickly identify security weaknesses in source code or small projects. It combines multi-agent analysis, Guardrails validation, and LangChain-based executive reporting to deliver both deep technical findings and high-level security insights.

Built for the Seagate GenAI Hackathon, Dev Guardian uses LLMs to analyze files, classify risks, map issues to OWASP categories, and generate clear, actionable reports for engineers, auditors, and business leaders.

Dev Guardian is a multi-agent AI-powered security analysis platform built for the Seagate GenAI Hackathon.  
It performs automated security scanning of source code using a hybrid workflow:

- **ScanAgent** → LLM-powered static security review  
- **RiskClassifierAgent** → Guardrails-enhanced severity normalization + OWASP mapping  
- **SummaryAgent** → Executive summary generator  
- **SupervisorAgent** → Automatically routes requests to the correct workflow  
- **LangChain Supervisor (optional)** → Executive report mode for managers and auditors  

The platform exposes a FastAPI-based web server with:
- **File Scanner** (single-file analysis)
- **Folder Scanner** (full project ZIP + mode selection)
- **Technical mode** (Guardrails + detailed findings table)
- **Executive mode** (LangChain narrative + findings)
- **JSON/PDF export**
- **Interactive HTML UI**

---

## 🚀 Features

### 🔍 Security Scanning Engine
- Scans Python, JS, TS, Java, C#, Go and other common source files  
- LLM-based security review with strict instructions  
- Detection of:
  - SQL/NoSQL injection  
  - Command injection  
  - XSS  
  - Hardcoded secrets  
  - Insecure file handling  
  - Unsafe cryptography  
  - Sensitive data exposure  
  - OWASP Top 10 issues  

### 🧠 Multi-Agent Architecture
Agents (from `multi_agent_workflow.py`):

1. **ScanAgent**  
   Reads files and sends them through the LLM for raw findings. :contentReference[oaicite:3]{index=3}

2. **RiskClassifierAgent**  
   Normalizes severity, adds OWASP mapping, enforces schema using Guardrails. :contentReference[oaicite:4]{index=4}

3. **SummaryAgent**  
   Produces an executive summary tailored for security architects. :contentReference[oaicite:5]{index=5}

4. **SupervisorAgent**  
   Decides which workflow to run based on user intent.  
   Example output:
   ```json
   {
     "selected_module": "security_scan",
     "reason": "User requested a full scan"
   }