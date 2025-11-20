GenAI Security Agent — Executive Overview
Purpose

The GenAI Security Agent is an intelligent, automated code-review system designed to help teams quickly identify security weaknesses in source code or small projects.

It delivers:

Faster security reviews

Consistent detection of critical risks

Clear, actionable findings for developers

Executive-ready summaries for decision makers

What the System Does

The agent scans uploaded code (single files or full project ZIPs) and produces a professional HTML risk report containing:

✔ Executive Summary

Overall risk level

Top issues requiring immediate attention

Key patterns or structural risks in the codebase

✔ Detailed Technical Findings

Severity (Critical / High / Medium / Low)

OWASP mapping

File locations

Clear fix recommendations

✔ Visual Insights

Severity distribution bar chart

Risk badges

JSON export for documentation or audit trails

Reports can also be saved as PDF directly from the browser.

Why It Matters

This tool reduces manual workload, accelerates security assessments, and supports governance teams with consistent, repeatable evaluation of code risks.

It is especially useful when:

Reviewing contractor code

Conducting internal security audits

Performing pre-deployment checks

Supporting engineering teams with regular hygiene scans

Demonstrating compliance with security frameworks

How It Works (High-Level)
1. Multi-Agent AI Workflow

The engine uses a 3-agent pipeline to analyze risks:

Scan Agent

Reviews project code

Detects risky patterns (injection, secrets, unsafe operations)

Risk Classifier Agent

Normalizes severity (Critical → Info)

Adds OWASP-style classification

Ensures correct structure using Guardrails

Summary Agent

Produces a concise executive-level interpretation

Highlights themes, business impacts, and recommended actions

A Supervisor Agent orchestrates the flow and selects the correct workflow based on user instructions.

2. Two Reporting Modes
Technical Mode (default)

Detailed findings for engineers

Prioritized remediation list

Guardrail-enforced formats

Best for code owners, DevSecOps, engineering teams

Executive Mode

Uses a LangChain-powered supervisor

Produces a management-oriented narrative

Ideal for directors, auditors, risk teams, and leadership

Both modes deliver the same findings table, but Executive Mode adds tailored high-level interpretation.

3. User Interface

Accessible at:

/ui


The UI supports two workflows:

✔ File Scanner

Upload a single file (.py, .js, .cs, etc.)
→ Immediate HTML report

✔ Folder Scanner (ZIP)

Upload a ZIP of a project
→ Choose Technical or Executive mode
→ Full codebase scan and report

Simple, fast, non-technical workflow for all stakeholders.

4. Example Outputs

The system generates:

➤ Executive Summary (sample)

“Overall risk is HIGH. The project contains critical injection vulnerabilities and embedded credentials.
Immediate attention is required to prevent exploitability in production.”

➤ Finding Example

Severity: High

Title: Unsanitized input used in SQL query

File: /src/user_service.py

Recommendation: “Use parameterized queries or ORM.”

5. Benefits for the Organization
Security

Detect critical issues before deployment

Reduce exposure to vulnerabilities

Increase consistency of reviews

Productivity

Accelerates code evaluation

Reduces manual reviewer burden

Simple UI for both devs and non-technical staff

Governance & Compliance

Supports audit evidence

Standardized output

Strengthens internal controls and development policy enforcement

6. Deployment & Access

The system runs as a FastAPI web service and is compatible with standard enterprise environments.

A bookmarkable web UI is included at:

http://<server>:8003/ui


No command-line usage required for end-users.

7. Roadmap

Future enhancements:

Integration with CI/CD pipelines (auto scanning)

Moonshot red-teaming module

AI Verify compatibility

Expanded OWASP mappings

Knowledge-base backed remediation assistant

Dashboard for multiple scan histories

8. Contact & Ownership

This project is designed for internal security and engineering enhancement.
Please consult your security governance or architecture lead for:

Access requests

Extensions

Audit alignment

Integration with development workflows