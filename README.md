# Dev Guardian

**GenAI-Powered Security Agent** — an intelligent, automated code-review system that identifies security weaknesses in source code and projects using a multi-agent LLM workflow.

Built for the **Seagate GenAI Hackathon** and extended with blue team governance controls inspired by **AISB Singapore 2026**.

🌐 **Live Demo:** https://devguardian-urielle-ai.up.railway.app/ui

---

## What It Does

Dev Guardian combines multi-agent analysis, Guardrails validation, and LangChain-based executive reporting to deliver both deep technical findings and high-level security insights — for engineers, auditors, and business leaders.

```
[File / ZIP Upload]
       ↓
[ScanAgent]          → LLM-powered static security review
       ↓
[RiskClassifierAgent] → Severity normalisation + OWASP mapping
       ↓
[SummaryAgent]       → Executive summary or technical report
       ↓
[PDF / JSON Report]  → Downloadable output
```

---

## 🚀 Features

### 🔍 Security Scanning Engine
- Scans Python, JS, TS, Java, C#, Go and other common source files
- LLM-based security review with strict OWASP-aligned instructions
- Detects:
  - SQL / NoSQL / Command injection
  - Cross-Site Scripting (XSS)
  - Hardcoded secrets and API keys (including base64-obfuscated variants)
  - Insecure cryptography (MD5, SHA-1, disabled TLS, weak random)
  - Unsafe deserialisation (pickle, eval)
  - Sensitive data exposure and plaintext PII storage
  - Insecure file handling and path traversal
  - CSRF, open redirects
  - Full OWASP Top 10 coverage

### 🧠 Multi-Agent Architecture

| Agent | Role | Model |
|---|---|---|
| `ScanAgent` | LLM-powered static security review | `gpt-4.1-mini` |
| `RiskClassifierAgent` | Severity normalisation + OWASP mapping | `gpt-4.1-nano` |
| `SummaryAgent` | Technical or executive summary generation | `gpt-4.1-mini` |
| `SupervisorAgent` | Routes requests to the correct workflow | `gpt-4.1-nano` |

### 🌐 Web Interface (FastAPI)
- **File Scanner** — single-file analysis
- **Folder Scanner** — full project ZIP with mode selection
- **Technical mode** — detailed findings table for engineers
- **Executive mode** — LangChain narrative for managers and auditors
- **JSON + PDF export** — downloadable reports
- **Interactive HTML UI** — browser-based at `/ui`

---

## 🔒 Blue Team Governance (AISB Singapore 2026)

Dev Guardian was extended with a three-layer token control and threat-modelled governance framework as part of AISB Singapore 2026 blue team testing.

### Layer 1 — OpenAI Platform Controls
- Monthly budget cap with spend alerts at 50% / 80% / 100%
- Tier 1 TPM limits verified per model

### Layer 2 — Per-Agent Model Selection
Replaced single global model with purpose-scoped assignments (~90% cost reduction):

```python
SCAN_MODEL       = "gpt-4.1-mini"   # Core vulnerability detection
CLASSIFY_MODEL   = "gpt-4.1-nano"   # JSON normalisation only
SUMMARY_MODEL    = "gpt-4.1-mini"   # Narrative generation
SUPERVISOR_MODEL = "gpt-4.1-nano"   # Routing JSON only
```

### Layer 3 — Application-Level Controls
| Control | Implementation |
|---|---|
| `max_output_tokens` per agent | 150–1500 tokens, purpose-scoped |
| File size gate | Reject >50KB single file before API call |
| Folder size gate | Reject >200KB aggregate before API call |
| tiktoken pre-flight | Estimate tokens locally before dispatch |
| Input truncation | Cap at 8,000 tokens, partial scan continues |
| JSON mode enforcement | `json_object` on 3 of 4 agents |
| Token usage audit log | `token_usage.log` per agent call |

---

## 🧪 Test Results — AISB Singapore 2026

**Final Score: 100/100 · 7/7 PASS · Production Ready**

| TC | Test | Findings | Result |
|---|---|---|---|
| TC-01 | Clean Baseline | 0 | ✅ Zero false positives |
| TC-02 | Hardcoded Secrets | 1 grouped | ✅ All 7 patterns + b64 detected |
| TC-03 | Injection Vulns | 7 | ✅ SQL, command, path traversal |
| TC-04 | Prompt Injection | 1 | ✅ Adversarial strings fully resisted |
| TC-05 | Weak Cryptography | 9 (web) | ✅ MD5, SHA1, TLS, pickle, random |
| TC-06 | XSS / Web Vulns | 10 | ✅ DOM XSS, eval, redirect, CSRF |
| TC-07 | Folder Scan (ZIP) | 12 (web) | ✅ 4 files, 11 CRITICAL, 1 HIGH |

See `Testing/` for full test suite and `Testing/README.md` for methodology.

---

## 📁 Project Structure

```
dev-guardian/
├── src/
│   ├── ai_agent.py                    # ScanAgent + Layer 2+3 controls
│   ├── multi_agent_workflow.py        # All agents + orchestration
│   ├── api_server.py                  # FastAPI server + UI
│   ├── guardrails_utils.py            # Schema enforcement
│   ├── langchain_supervisor_workflow.py # Executive report mode
│   └── report_html.py                 # HTML report generator
├── Testing/
│   ├── AISB test plan/                # TC-01 to TC-07 test files
│   └── README.md                      # Test methodology + results
├── docs/                              # Technical documentation
├── samples/                           # Example scan targets
├── requirements.txt
└── README.md
```

---

## ⚡ Quick Start

### Prerequisites
- Python 3.11+
- OpenAI API key (Tier 1 account recommended)

### Installation

```bash
git clone https://github.com/wholidi/dev-guardian.git
cd dev-guardian
pip install -r requirements.txt
```

### Configuration

```bash
# Set environment variables (never hardcode)
export OPENAI_API_KEY="sk-..."
export USE_REAL_LLM="True"
```

### Run locally

```bash
python -m uvicorn src.api_server:app --host 0.0.0.0 --port 8080
```

Open http://localhost:8080/ui in your browser.

### Run a scan via CLI

```python
import sys
sys.path.insert(0, '.')
from pathlib import Path
from src.multi_agent_workflow import security_scan_workflow

result = security_scan_workflow(Path('your_file.py'))
print('Findings:', len(result['findings']))
print('Summary:', result['summary'])
```

---

## 🚢 Deploy to Railway

1. Fork this repo
2. Connect to Railway → New Project → Deploy from GitHub
3. Set environment variables in Railway Dashboard:
   - `OPENAI_API_KEY` = your key
   - `USE_REAL_LLM` = `True`
4. Railway auto-deploys on every push

---

## 🛡️ STRIDE Threat Model

Dev Guardian's four trust boundaries:

```
[User / File Upload]
        ↓
[FastAPI Endpoint]            ← Input validation + size gates
        ↓
[ScanAgent / LLM]             ← Prompt injection hardening
        ↓
[RiskClassifier / Guardrails] ← Schema enforcement
        ↓
[Report Output HTML/PDF]      ← Output sanitisation
```

Each Layer 3 control maps to a specific STRIDE threat — no blanket blocking.

---

## 📋 Requirements

```
openai
fastapi
uvicorn
python-dotenv
httpx
tiktoken
langchain
langchain-openai
guardrails-ai
pydantic
```

---

## 🔗 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [AISB Singapore 2026](https://aisb.dev)
- [OpenAI API Rate Limits](https://platform.openai.com/docs/guides/rate-limits)
- [Railway Deployment](https://railway.app)

---

## ⚠️ Disclaimer

Dev Guardian is a security research and educational tool. The `Testing/` directory contains synthetic vulnerability patterns for scanner validation only — no real credentials or production data. All test secrets are non-functional.

---

*Built by Urielle AI Audit · Blue Team Governance*

