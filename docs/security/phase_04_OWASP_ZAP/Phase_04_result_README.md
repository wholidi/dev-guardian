# Dev Guardian — Phase 04 OWASP ZAP Operational Validation

**Urielle AI Audit · AISB Singapore 2026 · Blue Team Governance**

---

# Overview

Phase 04 represents the final operational validation stage for Dev Guardian using:

* OWASP ZAP 2.17.0
* Active DAST validation
* Runtime SSRF probing
* Injection resistance testing
* Security header verification
* Path traversal validation
* Remediation lifecycle tracking
* Release gate governance

This phase validates the live operational behavior of Dev Guardian after all Phase 03 security fixes were deployed.

---

# Phase 04 Objectives

The goals of this phase were to:

* Independently verify all deployed security fixes
* Confirm runtime protections under active scanning
* Validate injection resistance at HTTP boundary
* Confirm SSRF protections against cloud metadata paths
* Validate ZIP extraction runtime protections
* Confirm XSS sanitisation behavior
* Validate release readiness for pilot deployment
* Establish operational remediation tracking

---

# Validation Environment

| Item           | Value                   |
| -------------- | ----------------------- |
| Scanner        | OWASP ZAP 2.17.0        |
| Target         | `http://127.0.0.1:8000` |
| Version        | `api_server.py v2.2`    |
| Scan Date      | 09 May 2026             |
| Total Requests | 1,210                   |
| Unique URLs    | 20                      |
| Environment    | Local FastAPI runtime   |

---

# Runtime Security Architecture

Dev Guardian applies layered runtime governance controls across:

```text id="yb4nrg"
[HTTP Upload Request]
        ↓
[FastAPI Validation Boundary]
        ↓
[LLM ScanAgent]
        ↓
[RiskClassifier / Guardrails]
        ↓
[Security Middleware]
        ↓
[HTML / JSON / PDF Output]
```

---

# Release Gate Status

| Gate                      | Result     |
| ------------------------- | ---------- |
| CRITICAL findings         | 0          |
| HIGH findings             | 0          |
| ZIP Slip protection       | VERIFIED   |
| Security headers          | VERIFIED   |
| Filename XSS sanitisation | VERIFIED   |
| SSRF live probes          | VERIFIED   |
| Injection resistance      | VERIFIED   |
| CORS configuration        | VERIFIED   |
| Error page disclosure     | NONE       |
| OWASP LLM Top 10 baseline | 10/10 PASS |
| CSRF protection           | OPEN       |
| CSP form-action directive | OPEN       |

---

# Final Release Decision

## ✅ APPROVED FOR PASSWORD-GATED PILOT

All CRITICAL and HIGH findings were eliminated.

Remaining MEDIUM findings:

* CSRF middleware
* CSP form-action directive
* accepted inline CSP exceptions

Public launch remains blocked until:

```text id="umqmz4"
CSRF protection is implemented
```

---

# ZAP Scan Summary

## Passive Baseline Scan

Validated:

* security headers
* CSP deployment
* server disclosure removal
* CORS configuration

Result:

```text id="my4dz5"
0 HIGH
0 CRITICAL
```

Confirmed headers:

* HSTS
* CSP
* X-Content-Type-Options
* X-Frame-Options
* Cache-Control
* Referrer-Policy

---

## Active /health Scan

Validated:

* endpoint method restrictions
* injection rejection behavior
* invalid route handling

Observed:

```text id="x1x49i"
HTTP 405
HTTP 404
```

Result:

```text id="7n2d8h"
Injection attempts rejected
```

---

## Active /ui Scan

Validated:

* filename sanitisation
* CSP runtime behavior
* upload boundary validation
* XSS resistance

Result:

```text id="xghsvq"
0 XSS findings
```

---

## Full Active Scan

Validated:

* SSRF attempts
* path traversal attempts
* malformed multipart uploads
* SQL injection probes
* shell injection probes

Total requests:

```text id="q5g6oe"
1,000 active requests
```

Result:

```text id="kp6vzy"
0 HIGH
0 CRITICAL
```

---

# HTTP Response Analysis

| Code | Count | Meaning                                           |
| ---- | ----- | ------------------------------------------------- |
| 422  | 841   | FastAPI schema validation blocked malformed input |
| 404  | 117   | SSRF/path probes not routable                     |
| 200  | 41    | Valid endpoint responses                          |
| 405  | 4     | Invalid methods rejected                          |
| 307  | 1     | Internal redirect                                 |

Key finding:

> FastAPI validation boundary prevented malformed injection payloads from reaching application logic.

---

# Runtime Validation Results

## TS-01 — Prompt Injection

Validated:

* instruction override resistance
* jailbreak resistance
* prompt isolation

Result:

```text id="j2onxq"
PASS
```

---

## TS-02 — SSRF / RCE

Validated:

* AWS metadata paths
* GCP metadata paths
* Azure metadata paths
* Oracle metadata paths

Result:

```text id="f4d5wx"
All 12 IMDS paths → HTTP 404
```

No live SSRF confirmed.

---

## TS-03 — ZIP Slip / Path Traversal

Runtime protection:

```python id="pqrd4g"
_safe_extract()
```

Validated:

* ../../ traversal
* URL-encoded traversal
* Windows traversal
* null-byte payloads
* absolute paths

Result:

```text id="9oh29n"
0 traversal findings in 1,000 requests
```

---

## TS-04 — Resource Exhaustion

Validated:

* malformed request handling
* concurrent request behavior
* schema validation boundary

Observed:

```text id="s7kw5z"
841 → HTTP 422
```

Railway infrastructure rate limiting remains:

```text id="klm2av"
UNCONFIRMED
```

---

## TS-05 — XSS via Filename Reflection

Runtime protection:

```python id="xbr8zj"
_sanitise_filename()
```

Result:

```text id="xtefr4"
0 XSS findings
```

CSP confirmed active.

---

## TS-06 — Security Headers & CORS

Runtime protection:

```python id="c1p4sd"
SecurityHeadersMiddleware
```

Confirmed:

* HSTS
* CSP
* XFO
* XCTO
* Cache-Control
* Referrer-Policy

Result:

```text id="dnmklo"
PASS
```

---

# Security Fixes Confirmed

## Fix #1 — ZIP Slip Protection

Implemented:

```python id="f7jqva"
_safe_extract()
```

ZAP confirmed:

```text id="l4mxdy"
0 traversal findings
```

---

## Fix #2 — Security Middleware

Implemented:

```python id="qqvjlwm"
SecurityHeadersMiddleware
```

ZAP confirmed:

```text id="krp9kc"
All 6 headers present
```

---

## Fix #3 — Filename Sanitisation

Implemented:

```python id="qnvf2w"
_sanitise_filename()
```

ZAP confirmed:

```text id="iyflk7"
0 XSS findings
```

---

# Remaining Open Findings

## Required Before Public Launch

| Item                      | Severity |
| ------------------------- | -------- |
| CSRF protection           | MEDIUM   |
| CSP form-action directive | MEDIUM   |

---

## Accepted Risks

| Item                     | Rationale                         |
| ------------------------ | --------------------------------- |
| script-src unsafe-inline | required for Swagger UI           |
| style-src unsafe-inline  | required for current UI rendering |

---

## Post-Launch Improvements

| Item                       | Timeline          |
| -------------------------- | ----------------- |
| SRI hashes for Swagger CDN | 30 days           |
| Nonce-based CSP            | future hardening  |
| Burp Collaborator OOB SSRF | future validation |

---

# Four-Phase Security Progression

| Phase    | Focus                            | Result              |
| -------- | -------------------------------- | ------------------- |
| Phase 01 | OWASP manual validation          | 100/100             |
| Phase 02 | OWASP LLM Top 10                 | 96/100              |
| Phase 03 | StackHawk DAST                   | 0 HIGH / 0 CRITICAL |
| Phase 04 | OWASP ZAP operational validation | 0 HIGH / 0 CRITICAL |

---

# Strategic Significance

Phase 04 establishes Dev Guardian as:

* a runtime-aware AI security platform
* an operational AI governance experiment
* a multi-layer assurance workflow
* a verification-oriented security architecture
* a pilot-ready AI governance system

This phase also demonstrates:

* independent validation methodology
* remediation lifecycle tracking
* release-gate governance
* operational DAST maturity

---

# Repository Structure

```text id="4d9av8"
docs/
├── phase_04_OWASP_ZAP/
│   ├── architecture/
│   ├── evidence/
│   ├── reports/
│   ├── testing/
│   └── README.md
```

---

# Reports & Evidence

## Architecture

* dev_guardian_phase04_architecture.jsx

## Reports

* dev_guardian_phase04_zap_test_report.xlsx

## Evidence

* ZAP passive scan screenshots
* Active scan screenshots
* HTTP response logs
* Runtime SSRF validation
* Traversal validation evidence

---

# Future Direction

Future development focuses on:

* runtime governance telemetry
* SOC-style AI monitoring
* verification-layer architecture
* governance evidence generation
* NCAOS integration
* trust propagation models
* continuous runtime assurance

---

# References

* OWASP ZAP
* OWASP Top 10 for LLM Applications
* StackHawk
* FastAPI
* Railway

---

Generated by Urielle AI Audit · Blue Team Governance · May 2026
