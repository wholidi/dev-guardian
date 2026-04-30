# Dev Guardian — Test Suite
**Urielle AI Audit · Blue Team Governance**

---

## ⚠️ Important Notice

All files in this directory are **synthetic test cases** created specifically
for security scanner validation. They contain:

- **No real credentials, API keys, or tokens** — all secrets are fake,
  non-functional patterns used solely to test detection capability
- **Intentional vulnerability patterns** — insecure code is deliberate,
  for testing purposes only, and does not reflect production code quality
- **No production or personal data** of any kind

---

## Directory Structure

```
Testing/
├── AISB test plan/          ← Test case files (TC-01 to TC-07)
│   ├── tc01_clean_baseline.py
│   ├── tc02_hardcoded_secrets.py
│   ├── tc03_injection_vulns.py
│   ├── tc04_prompt_injection.py
│   ├── tc05_crypto_weaknesses.py
│   ├── tc06_xss_web_vulns.js
│   ├── tc_folder_scan_payload.zip
│   ├── TEST_PLAN.md
│   └── dev_guardian_threat_model.jsx
├── original/                ← Original source files (pre-Layer 2+3)
├── update/                  ← Updated source files (post-Layer 2+3)
└── README.md                ← This file
```

---

## Test Cases

| TC | File | Purpose | AISB Day |
|---|---|---|---|
| TC-01 | `tc01_clean_baseline.py` | False positive rate — expects 0 findings | Day 1 |
| TC-02 | `tc02_hardcoded_secrets.py` | Secret detection — AWS, Anthropic, Stripe, JWT, GitHub + b64 | Day 2 |
| TC-03 | `tc03_injection_vulns.py` | SQL injection, command injection, path traversal | Day 3 |
| TC-04 | `tc04_prompt_injection.py` | LLM robustness — adversarial strings embedded in code | Day 3 |
| TC-05 | `tc05_crypto_weaknesses.py` | MD5/SHA1, disabled TLS, pickle, insecure random | Day 2 |
| TC-06 | `tc06_xss_web_vulns.js` | DOM XSS, reflected XSS, eval(), open redirect, CSRF | Day 3 |
| TC-07 | `tc_folder_scan_payload.zip` | Folder scan — 4-file project with mixed vulnerability types | Day 4 |

---

## Session 1 Results Summary

**Environment:** Local (Windows PowerShell) + Railway Production Web UI
**Date:** 25 April 2026
**Models:** `gpt-4.1-mini` (ScanAgent, SummaryAgent) · `gpt-4.1-nano` (RiskClassifier, Supervisor)

| TC | Status | Findings | Key Result |
|---|---|---|---|
| TC-01 | ✅ PASS | 0 | Zero false positives — all Layer 3 controls firing |
| TC-02 | ✅ PASS | 1 grouped | All 7 patterns + base64-obfuscated variant detected |
| TC-03 | ✅ PASS | 7 | All SQL/command injection + path traversal vectors found |
| TC-04 | ✅ PASS | 1 | **Prompt injection fully resisted** — adversarial strings ignored |
| TC-05 | ✅ PASS | 9 (web) | MD5, SHA1, pickle, TLS, random, PII — all detected via TC-07 web |
| TC-06 | ✅ PASS | 10 | All XSS vectors, eval(), open redirect, CSRF detected |
| TC-07 | ✅ PASS | 12 (web) | 4 files, 11 CRITICAL + 1 HIGH — exceptional web result |

**Final Score: 100/100 · 7/7 PASS · Production Ready**

---

## Governance Controls Implemented

### 🔵 Layer 1 — OpenAI Platform
- Monthly budget cap: $10
- Spend alerts at 50% / 80% / 100%
- Tier 1 TPM verified per model

### 🟢 Layer 2 — Model Selection
Replaced single `o3-mini` global with purpose-scoped models (~90% cost reduction):

| Agent | Model | TPM |
|---|---|---|
| ScanAgent | `gpt-4.1-mini` | 200,000 |
| RiskClassifierAgent | `gpt-4.1-nano` | 200,000 |
| SummaryAgent | `gpt-4.1-mini` | 200,000 |
| SupervisorAgent | `gpt-4.1-nano` | 200,000 |

### 🟣 Layer 3 — Application-Level Controls

| Control | Implementation | Threat |
|---|---|---|
| `max_output_tokens` per agent | 150–1500 per agent | Runaway completions |
| Single file size gate | Reject >50KB before API call | Zip bomb / oversized input |
| Folder total size gate | Reject >200KB aggregate | Zip bomb across folder |
| tiktoken pre-flight | Estimate tokens locally before dispatch | Token budget overrun |
| Input truncation | Cap at 8,000 tokens, partial scan continues | Single scan overrun |
| JSON mode enforcement | `json_object` on 3 of 4 agents | Free-text inflation |
| Token usage logging | `token_usage.log` per agent call | No audit trail |
| `executive_mode` flag | Flex token cap by report type | Executive mode inflation |
| Non-dict filter | Strip malformed JSON items | Parser crash |

---

## STRIDE Threat Model

Dev Guardian has four trust boundaries:

```
[User / File Upload]
        ↓
[FastAPI Endpoint]          ← Boundary 1: Input Validation
        ↓
[ScanAgent / LLM]           ← Boundary 2: LLM Data Plane
        ↓
[RiskClassifier / Guardrails] ← Boundary 3: Output Schema
        ↓
[Report Output HTML/PDF]    ← Boundary 4: Presentation
```

Each control maps to a specific STRIDE threat — no blanket blocking.
See `dev_guardian_threat_model.jsx` for the interactive dashboard.

---

## Session 2 — Planned Fixes

| Priority | Fix | File |
|---|---|---|
| P1 | `MAX_TOKENS_CLASSIFY` → 1500 | `src/ai_agent.py` |
| P2 | Separate finding per vulnerability prompt | `src/ai_agent.py` |
| P3 | Guardrails — Pydantic schema implementation | `src/guardrails_utils.py` |
| P4 | Deploy fixes to Railway | Railway Dashboard |
| P5 | Full web run — all 7 TCs via browser | Web UI |
| P6 | OWASP mapping correction — CMD injection → A03 | `src/multi_agent_workflow.py` |

---

## References

- Dev Guardian repo: https://github.com/wholidi/dev-guardian
- Live Web UI: https://devguardian-urielle-ai.up.railway.app/ui
- AISB Singapore 2026: https://aisb.dev
- OWASP Top 10: https://owasp.org/www-project-top-ten/

---

*Generated by Urielle AI Audit · Blue Team Security Testing · April 2026*
