# Dev Guardian

**Runtime AI Security Validation & Governance Platform**

Built by **Urielle AI Audit** as a multi-phase AI security assurance initiative combining:

* OWASP LLM Top 10 validation
* Runtime governance controls
* Multi-agent AI security workflows
* DAST verification
* STRIDE threat modelling
* Operational release-gate validation

🌐 Live Demo
https://devguardian-urielle-ai.up.railway.app/ui

📦 GitHub Repository
https://github.com/wholidi/dev-guardian

---

# Overview

Dev Guardian is a governance-oriented AI security platform designed to validate source code, detect vulnerabilities, evaluate runtime risks, and generate structured audit evidence using multi-agent LLM workflows.

The project evolved through four security validation phases:

| Phase    | Focus                                 | Result              |
| -------- | ------------------------------------- | ------------------- |
| Phase 01 | OWASP security foundations            | 100/100             |
| Phase 02 | OWASP LLM Top 10 validation           | 96/100              |
| Phase 03 | StackHawk DAST pre-release validation | 0 HIGH / 0 CRITICAL |
| Phase 04 | OWASP ZAP operational validation      | 0 HIGH / 0 CRITICAL |

---

# Architecture Overview

Dev Guardian applies layered runtime governance controls across:

```text
[File Upload]
        ↓
[FastAPI Validation Boundary]
        ↓
[LLM ScanAgent]
        ↓
[RiskClassifier / Guardrails]
        ↓
[Security Middleware]
        ↓
[HTML / JSON / PDF Reporting]
```

The architecture combines:

* AI-assisted security review
* runtime governance controls
* STRIDE threat modelling
* schema enforcement
* operational DAST validation

---

# Multi-Agent Architecture

| Agent               | Role                                   | Model        |
| ------------------- | -------------------------------------- | ------------ |
| ScanAgent           | LLM-powered vulnerability analysis     | gpt-4.1-mini |
| RiskClassifierAgent | Severity normalisation + OWASP mapping | gpt-4.1-nano |
| SummaryAgent        | Executive and technical reporting      | gpt-4.1-mini |
| SupervisorAgent     | Workflow routing and orchestration     | gpt-4.1-nano |

---

# Core Capabilities

## AI Security Validation

* OWASP Top 10 detection
* OWASP LLM Top 10 testing
* Prompt injection resistance
* Supply-chain vulnerability detection
* SSRF pattern detection
* XSS and injection analysis
* ZIP traversal validation
* Runtime governance evaluation

---

## Governance Controls

### Layer 1 — OpenAI Platform Governance

* API budget caps
* spend alerts
* TPM verification

### Layer 2 — Model Governance

Purpose-scoped model assignment:

* gpt-4.1-mini for security analysis
* gpt-4.1-nano for classification and routing

### Layer 3 — Runtime Application Controls

* max_output_tokens enforcement
* token pre-flight estimation
* JSON mode enforcement
* file size gates
* folder aggregate limits
* Guardrails validation
* token usage logging
* output integrity protection

---

# Runtime Security Features

## Input Layer Protections

* MIME verification
* upload size gates
* ZIP traversal validation
* filename sanitisation
* schema validation boundaries

## LLM Runtime Protections

* prompt isolation
* XML wrapping
* structured JSON responses
* OWASP LLM rule mapping
* token truncation

## Output Governance

* Pydantic schema enforcement
* severity normalization
* findings-only reporting
* HTML escaping

## Security Middleware

* CSP headers
* HSTS
* X-Frame-Options
* X-Content-Type-Options
* Cache-Control
* Referrer-Policy

---

# Four-Phase Security Assurance Program

## Phase 01 — Security Foundations

Validated:

* baseline OWASP vulnerability detection
* prompt injection resistance
* STRIDE threat modelling
* governance-layer architecture

Result:

```text
100/100 · 7/7 PASS
```

Documentation:

```text
docs/phase_01/
```

---

## Phase 02 — OWASP LLM Top 10

Validated:

* LLM01–LLM10 risks
* governance-aware findings
* structured output controls
* AI-specific attack patterns

Result:

```text
96/100
```

Documentation:

```text
docs/phase_02/
```

---

## Phase 03 — StackHawk DAST Validation

Validated:

* active DAST scanning
* runtime middleware hardening
* ZIP Slip protection
* security headers
* release-gate governance

Result:

```text
0 HIGH
0 CRITICAL
```

Documentation:

```text
docs/phase_03_DAST_Stackhawk/
```

---

## Phase 04 — OWASP ZAP Operational Validation

Validated:

* active runtime SSRF probing
* injection resistance
* path traversal protection
* operational remediation tracking
* pilot release readiness

Result:

```text
0 HIGH
0 CRITICAL
```

Current release status:

```text
APPROVED FOR PASSWORD-GATED PILOT
```

Documentation:

```text
docs/phase_04_OWASP_ZAP/
```

---

# DAST & Runtime Validation

## StackHawk

Validated:

* API crawling
* multipart fuzzing
* endpoint exposure
* active scanning

## OWASP ZAP

Validated:

* SSRF probes
* injection attempts
* path traversal attempts
* CSP validation
* runtime HTTP boundary behaviour

---

# Security Fixes Implemented

## ZIP Slip Protection

```python
_safe_extract()
```

## Filename XSS Protection

```python
_sanitise_filename()
```

## Security Middleware

```python
SecurityHeadersMiddleware
```

---

# Repository Structure

```text
dev-guardian/
├── src/
├── tests/
├── docs/
│   ├── phase_01/
│   ├── phase_02/
│   ├── phase_03_DAST_Stackhawk/
│   └── phase_04_OWASP_ZAP/
├── requirements.txt
└── README.md
```

---

# Quick Start

## Installation

```bash
git clone https://github.com/wholidi/dev-guardian.git
cd dev-guardian
pip install -r requirements.txt
```

---

## Configure Environment

```bash
export OPENAI_API_KEY="sk-..."
export USE_REAL_LLM="True"
```

---

## Run Locally

```bash
python -m uvicorn src.api_server:app --host 0.0.0.0 --port 8080
```

Open:

```text
http://localhost:8080/ui
```

---

# Strategic Direction

Future development focuses on:

* runtime AI telemetry
* verification-layer architecture
* SOC-style AI monitoring
* governance evidence generation
* NCAOS integration
* trust propagation models
* continuous runtime assurance

---

# References

* OWASP Top 10
* OWASP Top 10 for LLM Applications
* OWASP ZAP
* StackHawk
* FastAPI
* Railway

---

# Disclaimer

Dev Guardian is a security research and governance engineering project.

The repository includes synthetic vulnerability patterns and controlled attack simulations for educational and validation purposes only.

No production credentials or live malicious payloads are included.

---

Built by Urielle AI Audit · Blue Team Governance · Singapore
