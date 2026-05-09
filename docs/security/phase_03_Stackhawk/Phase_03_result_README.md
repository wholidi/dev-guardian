# Dev Guardian — Phase 03 Pre-Release Security Validation

**Urielle AI Audit · AISB Singapore 2026 · Blue Team Governance**

---

# Overview

Phase 03 represents the full pre-release security validation cycle for Dev Guardian.

This phase combines:

* OWASP LLM Top 10 validation
* StackHawk DAST scanning
* OWASP ZAP active scanning
* Runtime attack simulation
* Infrastructure hardening
* Release-gate governance
* Security middleware deployment
* Runtime extraction protection

The objective of Phase 03 is to validate Dev Guardian as a production-usable AI security platform before pilot deployment.

---

# Security Validation Scope

## White-Box Testing

OWASP LLM Top 10 manual testing:

* Prompt injection
* Sensitive data disclosure
* Supply chain vulnerabilities
* Excessive agency
* System prompt leakage
* RAG / embedding weaknesses
* Misinformation risks
* Unbounded consumption

---

## Black-Box Testing

DAST / network-layer testing via:

* StackHawk
* OWASP ZAP 2.17.0
* Active HTTP attack simulation
* Multipart upload fuzzing
* SSRF probes
* ZIP traversal attacks
* XSS payload testing

---

# Architecture Overview

Dev Guardian applies layered runtime security controls across:

```text
[File Upload]
        ↓
[FastAPI Input Layer]
        ↓
[LLM ScanAgent]
        ↓
[RiskClassifier / Guardrails]
        ↓
[HTML / JSON / PDF Reporting]
```

---

# Phase 03 Security Objectives

The goals of this phase were to:

* Validate pilot-launch readiness
* Confirm runtime hardening effectiveness
* Test DAST exposure surfaces
* Validate ZIP extraction security
* Validate upload sanitisation
* Verify security headers deployment
* Validate LLM robustness under attack
* Establish release gates

---

# Release Gate Status

| Gate                        | Result     |
| --------------------------- | ---------- |
| CRITICAL findings           | 0          |
| HIGH findings               | 0          |
| OWASP LLM Top 10            | 10/10 PASS |
| Final OWASP Score           | 96 / 100   |
| ZIP Slip protection         | VERIFIED   |
| Security headers            | VERIFIED   |
| Filename XSS sanitisation   | VERIFIED   |
| Stack traces in error pages | NONE       |
| CORS misconfiguration       | NONE       |
| CSRF protection             | OPEN       |

---

# Pilot Release Decision

## ✅ APPROVED FOR PASSWORD-GATED PILOT

The application passed:

* StackHawk validation
* OWASP ZAP validation
* OWASP LLM testing
* Runtime probe testing

Remaining blocker before public release:

```text
CSRF middleware deployment
```

---

# Runtime Security Architecture

## Boundary 1 — Input Layer

Controls:

* File extension allowlist
* MIME verification
* Size gates
* ZIP traversal validation
* Rate limiting preparation

Threats mitigated:

* Zip bombs
* Path traversal
* Malformed uploads
* SSRF payload ingress

---

## Boundary 2 — LLM Data Plane

Controls:

* Prompt isolation
* XML wrapping
* JSON-only mode
* Token governance
* OWASP LLM detection rules

Threats mitigated:

* Prompt injection
* Jailbreaks
* Context poisoning
* Token exhaustion

---

## Boundary 3 — Output Governance

Controls:

* Pydantic schema enforcement
* Separate-finding rule
* Severity normalization
* Guardrails validation

Threats mitigated:

* Schema bypass
* Finding suppression
* Malformed outputs

---

## Boundary 4 — Presentation Layer

Controls:

* HTML escaping
* Filename sanitisation
* CSP middleware
* Security headers

Threats mitigated:

* Stored XSS
* Reflected XSS
* Clickjacking
* MIME confusion

---

# OWASP LLM Progression

| Category                          | Phase 01 | Phase 02 |
| --------------------------------- | -------- | -------- |
| LLM01 Prompt Injection            | PASS     | PASS     |
| LLM02 Sensitive Info Disclosure   | PARTIAL  | PASS     |
| LLM03 Supply Chain / Pickle RCE   | PASS     | PASS     |
| LLM04 Data & Model Poisoning      | PASS     | PASS     |
| LLM05 Improper Output Handling    | PASS     | PASS     |
| LLM06 Excessive Agency            | PASS     | PASS     |
| LLM07 System Prompt Leakage       | PARTIAL  | PASS     |
| LLM08 Vector & Embedding Weakness | PASS     | PASS     |
| LLM09 Misinformation              | FAIL     | PASS     |
| LLM10 Unbounded Consumption       | PARTIAL  | PASS     |

Final Result:

> 72/100 → 96/100 (+24 improvement)

---

# Manual Probe Testing

## TS-01 — Prompt Injection

Validated:

* instruction override resistance
* DAN-style injection resistance
* SSRF payload handling
* SSTI payload handling

Result:

```text
PASS
```

---

## TS-02 — SSRF / RCE

Validated:

* IMDSv1 probes
* internal network reconnaissance
* environment variable exposure attempts

Result:

```text
PASS
```

---

## TS-03 — ZIP Slip / Path Traversal

Runtime fix deployed:

```python
_safe_extract()
```

Protection:

* ../../ traversal
* URL-encoded traversal
* Windows path traversal
* absolute paths
* null-byte payloads

Result:

```text
HTTP 400 returned
```

---

## TS-04 — Resource Exhaustion

Validated:

* upload size handling
* malformed payload rejection
* concurrent request handling

Result:

```text
GOOD DETECTION
```

---

## TS-05 — XSS via Filename Reflection

Runtime fix deployed:

```python
_sanitise_filename()
```

Result:

```text
10/10 payloads blocked
```

---

## TS-06 — Security Headers & CORS

Security middleware deployed:

```python
SecurityHeadersMiddleware
```

Headers confirmed by ZAP:

* HSTS
* CSP
* X-Frame-Options
* X-Content-Type-Options
* Cache-Control
* Referrer-Policy

Result:

```text
PASS
```

---

# DAST Validation

## StackHawk

Validated:

* API crawling
* endpoint exposure
* multipart fuzzing
* active scanning

Result:

```text
0 HIGH
0 CRITICAL
```

---

## OWASP ZAP

Validated:

* active scan probes
* SSRF attempts
* injection attempts
* CSP validation
* runtime traversal protection

Result:

```text
0 HIGH
0 CRITICAL
```

---

# Security Fixes Deployed

## Fix #1 — ZIP Slip Protection

Implemented:

```python
_safe_extract()
```

---

## Fix #2 — Security Middleware

Implemented:

```python
SecurityHeadersMiddleware
```

---

## Fix #3 — Filename Sanitisation

Implemented:

```python
_sanitise_filename()
```

---

# Remaining Open Items

## Required Before Public Launch

| Item                                 | Priority    |
| ------------------------------------ | ----------- |
| CSRF middleware                      | REQUIRED    |
| Railway infrastructure rate limiting | RECOMMENDED |
| form-action CSP tightening           | RECOMMENDED |

---

## Post-Launch Improvements

| Item                       | Timeline         |
| -------------------------- | ---------------- |
| SRI hashes for Swagger CDN | 30 days          |
| Nonce-based CSP            | future hardening |

---

# Repository Structure

```text
docs/
├── phase_03_DAST_Stackhawk/
│   ├── architecture/
│   ├── evidence/
│   ├── reports/
│   ├── testing/
│   └── README.md
```

---

# Reports & Evidence

## Architecture

* dev_guardian_phase03_architecture.jsx

## Reports

* dev_guardian_phase03_stackhawk_test_report.xlsx
* Phase_03.md

## Evidence

* ZAP screenshots
* StackHawk findings
* Active scan logs
* Runtime probe results

---

# Strategic Direction

Future phases focus on:

* Runtime AI telemetry
* Verification-layer architecture
* SOC-style AI monitoring
* Governance evidence generation
* NCAOS signal integration
* Trust propagation models
* Continuous runtime verification

---

# References

* OWASP Top 10 for LLM Applications
* OWASP ZAP
* StackHawk
* FastAPI
* Railway

---

Generated by Urielle AI Audit · Blue Team Governance · May 2026
