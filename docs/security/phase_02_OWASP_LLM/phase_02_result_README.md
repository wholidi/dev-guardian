# Dev Guardian — Phase 02 OWASP LLM Top 10 Validation

**Urielle AI Audit · Blue Team Governance**


🔗 Quick Links
🌐 Live Test UI
https://devguardian-urielle-ai.up.railway.app/ui
📦 GitHub Repository
https://github.com/wholidi/dev-guardian
📘 Reference

---

# Overview

Phase 02 expands Dev Guardian from a traditional AI-assisted security scanner into a governance-oriented LLM security validation platform.

This phase introduces:

* OWASP LLM Top 10 testing
* AI governance risk evaluation
* Runtime security controls
* Multi-agent orchestration hardening=
* Structured output governance
* LLM-specific threat modeling
* Scanner robustness validation

The goal of Phase 02 is not only to detect classic vulnerabilities, but also to evaluate how AI systems behave under adversarial and governance-related conditions.

---

# Key Objectives

Phase 02 validates whether Dev Guardian can:

* Detect OWASP LLM01–LLM10 risks
* Resist prompt injection attacks
* Detect AI governance risks
* Identify excessive agency patterns
* Handle adversarial LLM outputs safely
* Maintain structured JSON integrity
* Generate audit-oriented security findings

---

# Architecture Overview

Dev Guardian uses four trust boundaries:

```text id="a9pc3u"
[File Upload]
        ↓
[FastAPI Input Layer]
        ↓
[ScanAgent / LLM Security Engine]
        ↓
[RiskClassifier / Guardrails]
        ↓
[HTML / PDF Reporting]
```

The architecture applies STRIDE threat modeling across all boundaries.

---

# Phase 02 Architecture Enhancements

## New Controls Introduced

### OWASP LLM Rule Engine

* LLM01–LLM10 detection patterns
* Governance-aware findings
* AI-specific attack classification

### Separate-Finding Rule

* One finding per vulnerability
* Reduced grouped-result ambiguity
* Improved JSON export consistency

### Runtime Token Governance

* 8,000 token truncation
* max_output_tokens enforcement
* token_usage.log audit trail

### Guardrails Hardening

* Strict Pydantic schema validation
* Enum-pinned severity levels
* Malformed JSON rejection

---

# Governance Boundaries

## Boundary 1 — Input Validation

Controls:

* File extension allowlist
* MIME verification
* Size gates
* Token pre-flight
* Railway rate limiting

Threats mitigated:

* Zip bombs
* MIME spoofing
* Token exhaustion
* SSRF vectors

---

## Boundary 2 — LLM Data Plane

Controls:

* XML content wrapping
* JSON-only responses
* Prompt isolation
* OWASP LLM rule mapping
* Input truncation

Threats mitigated:

* Prompt injection
* Jailbreaks
* False-clean verdicts
* Token overrun

---

## Boundary 3 — Output Schema

Controls:

* Pydantic validation
* Separate-finding enforcement
* Guardrails filtering
* Severity normalization

Threats mitigated:

* Schema bypass
* Severity downgrade
* Malformed output injection

---

## Boundary 4 — Presentation Layer

Controls:

* HTML escaping
* Findings-only PDF generation
* Executive-mode reporting

Threats mitigated:

* XSS in reports
* Sensitive data leakage
* Presentation-layer injection

---

# OWASP LLM Top 10 Coverage

| Category                             | Status  |
| ------------------------------------ | ------- |
| LLM01 — Prompt Injection             | PASS    |
| LLM02 — Sensitive Info Disclosure    | PARTIAL |
| LLM03 — Supply Chain Vulnerabilities | PASS    |
| LLM04 — Data & Model Poisoning       | PASS    |
| LLM05 — Improper Output Handling     | PASS    |
| LLM06 — Excessive Agency             | PASS    |
| LLM07 — System Prompt Leakage        | PARTIAL |
| LLM08 — Vector & Embedding Weakness  | PASS    |
| LLM09 — Misinformation               | FAIL    |
| LLM10 — Unbounded Consumption        | PARTIAL |

---

# Key Findings

## Strong Detection Areas

### LLM03 — Supply Chain Vulnerabilities

Dev Guardian successfully detected:

* pickle deserialization risks
* unsafe package installation
* torch.load RCE patterns
* dynamic plugin imports
* GPU side-channel access

### LLM05 — Improper Output Handling

The scanner correctly flagged:

* exec(LLM_output)
* os.system(LLM_command)
* stored XSS patterns

### LLM06 — Excessive Agency

The scanner identified:

* unrestricted tool access
* AI-driven financial actions
* unsafe autonomous decisions

This demonstrates governance-awareness beyond classic static analysis.

---

# Known Gaps

## LLM09 — Misinformation

Current scanner limitations:

* no semantic governance reasoning
* no role misrepresentation detection
* no ethics-aware rule engine

This represents the largest governance gap in Phase 02.

---

## LLM10 — Unbounded Consumption

Missing detections include:

* missing max_tokens rules
* missing rate-limit checks
* infinite context growth patterns

---

# Session 2 Bugs & Lessons

Several architectural issues were identified during validation:

| Issue                       | Resolution                 |
| --------------------------- | -------------------------- |
| pycache override            | cleared stale .pyc files   |
| JSON object vs array output | explicit array enforcement |
| wrong file uploaded         | file verification workflow |
| raw JSON summary rendering  | SummaryAgent narrative fix |

These findings significantly improved runtime reliability.

---

# Testing Methodology

Phase 02 testing used:

* OWASP LLM Top 10 synthetic test files
* Browser-based upload validation
* Technical and Executive reporting modes
* Structured JSON export verification
* Multi-file ZIP scans

---

# Aggregate Result

| Metric      | Result   |
| ----------- | -------- |
| PASS        | 6        |
| PARTIAL     | 3        |
| FAIL        | 1        |
| Final Score | 72 / 100 |

Status:

> Production-usable with known governance gaps.

---

# Repository Structure

```text id="jru6mc"
docs/
├── phase_02/
│   ├── architecture/
│   ├── evidence/
│   ├── reports/
│   ├── testing/
│   └── README.md
```

---

# Reports & Evidence

## Architecture

* dev_guardian_phase02_architecture.jsx

## Reports

* dev_guardian_owasp_phase_02_report.xlsx

## Testing

* OWASP LLM test files
* Folder scan ZIP tests
* Runtime JSON exports

---

# Strategic Direction

Future phases focus on:

* Runtime AI governance telemetry
* Verification-layer architecture
* SOC-style AI incident monitoring
* Trust propagation models
* NCAOS integration
* Governance evidence generation
* Independent DAST validation

---

# References

* OWASP Top 10 for LLM Applications
* AISB Singapore 2026
* StackHawk
* OWASP ZAP

---

Generated by Urielle AI Audit · Blue Team Governance · May 2026
