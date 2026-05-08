from dotenv import load_dotenv

load_dotenv()

import json
import re
from pathlib import Path
import tempfile
import zipfile
import html
import os
from typing import List, Dict, Any

from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse, HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .multi_agent_workflow import (
    run_multi_agent_workflow,
    run_workflow_with_supervisor,
)
from .langchain_supervisor_workflow import run_langchain_supervisor
from .ai_agent import analyze_file
from .report_html import findings_to_html

# -------------------------------------------------
# Filename sanitisation (fixes TS-05 XSS risk)
# Strips any character that is not alphanumeric, dash, underscore, or dot.
# Applied at every single-file upload boundary before the name is used in
# temp file creation or reflected into any HTML report.
# -------------------------------------------------

_SAFE_FILENAME_RE = re.compile(r"[^\w.\-]")   # keep: a-z A-Z 0-9 _ . -

def _sanitise_filename(raw: str) -> str:
    """
    Return a safe filename: only alphanumerics, dots, dashes, underscores.
    Falls back to 'upload' if the result would be empty after sanitisation.
    """
    name = Path(raw).name                         # strip any path component first
    name = _SAFE_FILENAME_RE.sub("_", name)       # replace unsafe chars with _
    name = name.strip("._")                       # strip leading/trailing dots & underscores
    return name or "upload"


# -------------------------------------------------
# ZipSlip-safe extraction
# -------------------------------------------------

def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    """
    Extract every member of a ZipFile to dest, rejecting any entry whose
    resolved output path escapes the destination directory.

    Protects against:
      - Classic traversal:      ../../etc/passwd
      - URL-encoded traversal:  %2e%2e%2fetc%2fpasswd  (zipfile decodes these)
      - Null-byte injection:    safe\x00.py/../../etc
      - Windows-style:          ..\\..\\ (zipfile normalises on all platforms)
      - Absolute paths:         /etc/passwd

    Raises ValueError listing all rejected entries so the caller can log
    or surface the error rather than silently skipping.
    """
    dest_resolved = dest.resolve()
    rejected: List[str] = []

    for member in zf.infolist():
        # Normalise the member name: strip leading slashes/dots that zipfile
        # may leave after its own sanitisation pass, then re-resolve.
        member_path = (dest_resolved / member.filename).resolve()
        try:
            member_path.relative_to(dest_resolved)
        except ValueError:
            rejected.append(member.filename)
            continue

        # Safe to extract this member
        zf.extract(member, path=dest)

    if rejected:
        raise ValueError(
            f"ZipSlip blocked: {len(rejected)} entry/entries with path traversal "
            f"rejected from ZIP archive: {rejected[:5]}"
            + (" …and more" if len(rejected) > 5 else "")
        )


# -------------------------------------------------
# FastAPI app
# -------------------------------------------------
app = FastAPI(
    title="Dev Guardian – AI Audit & Runtime Monitoring",
    version="1.0.0",
    description="Transforms AI behavior into audit-ready signals and governance evidence"
)

# -------------------------------------------------
# Security headers middleware (fixes TS-06 / TS-07)
# Adds all 5 headers confirmed missing by headers_cors_probe.py and StackHawk.
# -------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Suppress Railway infrastructure disclosure
        response.headers["Server"] = "Dev-Guardian"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# -------------------------------------------------
# Helper: HTML report with JSON injection
# -------------------------------------------------


def build_html_report_with_lc(
    summary: str,
    findings: List[Dict[str, Any]],
    lc_summary: str = "",
    mode: str = "technical",
) -> str:
    """
    Build an HTML report that:
    - Computes risk scoring from severities
    - Shows total findings + overall risk badge
    - Shows a refined executive summary
    - Optionally includes LangChain narrative (executive mode)
    - Renders a severity distribution chart
    - Renders a table of findings
    - Includes a placeholder for JSON download ({{REPORT_JSON}})
    """

    # --------- Severity counting & risk scoring ----------
    buckets = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for f in findings:
        sev = (f.get("severity") or "").strip().lower()
        if sev in buckets:
            buckets[sev] += 1
        elif "crit" in sev:
            buckets["critical"] += 1
        elif "high" in sev:
            buckets["high"] += 1
        elif "med" in sev:
            buckets["medium"] += 1
        elif "low" in sev:
            buckets["low"] += 1
        else:
            buckets["info"] += 1

    total = len(findings)

    # Simple overall risk rule-of-thumb
    if buckets["critical"] > 0:
        overall_risk = "Critical"
        risk_class = "risk-critical"
    elif buckets["high"] >= 2 or (buckets["high"] == 1 and buckets["medium"] >= 2):
        overall_risk = "High"
        risk_class = "risk-high"
    elif buckets["medium"] > 0:
        overall_risk = "Medium"
        risk_class = "risk-medium"
    elif total > 0:
        overall_risk = "Low"
        risk_class = "risk-low"
    else:
        overall_risk = "None"
        risk_class = "risk-none"

    # --------- Build nicer executive summary text ----------
    stats_line = (
        f"Total findings: {total}. "
        f"Critical: {buckets['critical']}, "
        f"High: {buckets['high']}, "
        f"Medium: {buckets['medium']}, "
        f"Low: {buckets['low']}."
    )

    summary_html = html.escape(summary or "").replace("\n", "<br/>")
    lc_html = html.escape(lc_summary or "").replace("\n", "<br/>")

    # --------- Build table rows ----------
    rows_html = []
    for f in findings:
        sev_raw = (f.get("severity") or "").upper()
        sev_key = (f.get("severity") or "").lower()
        sev_class = "severity-" + (
            "critical" if "crit" in sev_key
            else "high" if "high" in sev_key
            else "medium" if "med" in sev_key
            else "low" if "low" in sev_key
            else "info"
        )

        title = f.get("title") or ""
        location = f.get("location") or f.get("file", "")
        description = f.get("description") or ""
        recommendation = f.get("recommendation") or ""

        rows_html.append(
            f"""
            <tr>
              <td class="severity {sev_class}">{html.escape(sev_raw)}</td>
              <td>{html.escape(title)}</td>
              <td><code>{html.escape(location)}</code></td>
              <td>{html.escape(description)}</td>
              <td>{html.escape(recommendation)}</td>
            </tr>
            """
        )

    rows_block = "\n".join(rows_html)

    # --------- HTML with chart + PDF + JSON buttons ----------
    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>AI Security Findings</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f5f7fb;
      padding: 32px;
    }}
    .top-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }}
    h1 {{
      margin: 0;
    }}
    .subtle {{
      color: #555;
      margin-bottom: 16px;
    }}
    .risk-badge {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }}
    .risk-critical {{ background:#fee2e2; color:#b91c1c; }}
    .risk-high     {{ background:#fef3c7; color:#92400e; }}
    .risk-medium   {{ background:#e0f2fe; color:#075985; }}
    .risk-low      {{ background:#dcfce7; color:#166534; }}
    .risk-none     {{ background:#e5e7eb; color:#374151; }}

    .summary-box {{
      background: #fff;
      border-radius: 8px;
      padding: 16px 20px;
      margin-bottom: 24px;
      box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
    }}
    .summary-box h2 {{
      margin-top: 0;
      margin-bottom: 8px;
    }}
    .summary-section h3 {{
      margin-bottom: 4px;
      font-size: 15px;
    }}
    .summary-section p {{
      margin-top: 0;
      margin-bottom: 8px;
      font-size: 14px;
    }}

    .layout {{
      display: grid;
      grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }}
    .chart-card {{
      background: #fff;
      border-radius: 8px;
      padding: 12px 16px;
      box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
    }}
    .chart-card h3 {{
      margin-top: 0;
      font-size: 14px;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      background: #fff;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
    }}
    th, td {{
      padding: 10px 12px;
      vertical-align: top;
      font-size: 14px;
      border-bottom: 1px solid #e5e7eb;
    }}
    th {{
      background: #f3f4f6;
      text-align: left;
      font-weight: 600;
    }}
    tr:last-child td {{
      border-bottom: none;
    }}
    .severity {{
      font-weight: 700;
      text-transform: uppercase;
      text-align: center;
      width: 90px;
    }}
    .severity-critical {{ background:#fee2e2; color:#b91c1c; }}
    .severity-high     {{ background:#fef3c7; color:#92400e; }}
    .severity-medium   {{ background:#e0f2fe; color:#075985; }}
    .severity-low      {{ background:#dcfce7; color:#166534; }}
    .severity-info     {{ background:#e5e7eb; color:#374151; }}

    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
                   "Liberation Mono", "Courier New", monospace;
      background: #f3f4f6;
      padding: 2px 4px;
      border-radius: 4px;
      font-size: 12px;
    }}

    .btn-pdf, .btn-json {{
      border: 1px solid #d1d5db;
      background: #fff;
      padding: 6px 10px;
      border-radius: 6px;
      font-size: 13px;
      cursor: pointer;
    }}
    .btn-pdf:hover,
    .btn-json:hover {{
      background: #f3f4f6;
    }}

    @media print {{
      .btn-pdf, .btn-json {{ display: none; }}
      body {{ background:#fff; padding:16px; }}
    }}
  </style>
</head>
<body>
  <div class="top-bar">
    <div>
      <h1>AI Security Findings</h1>
      <div class="subtle">
        Overall risk: <span class="risk-badge {risk_class}">{overall_risk}</span>
        &nbsp;&nbsp;|&nbsp;&nbsp; Total findings: {total}
      </div>
    </div>
    <div style="display:flex; gap:10px;">
      <button class="btn-pdf" onclick="window.print()">Download as PDF</button>
      <button class="btn-json" onclick="downloadJson()">Download JSON</button>
    </div>
  </div>

  <div class="summary-box">
    <h2>Executive summary</h2>
    <div class="summary-section">
      <h3>Risk overview</h3>
      <p>{html.escape(stats_line)}</p>
    </div>
    {"<div class='summary-section'><h3>Technical summary</h3><p>" + summary_html + "</p></div>" if summary_html else ""}
    {("<div class='summary-section'><h3>AI narrative (LangChain)</h3><p>" + lc_html + "</p></div>") if lc_summary else ""}
  </div>

  <div class="layout">
    <div></div>
    <div class="chart-card">
      <h3>Severity distribution</h3>
      <canvas id="severityChart" width="300" height="260"></canvas>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Title</th>
        <th>File / Location</th>
        <th>Description</th>
        <th>Recommendation</th>
      </tr>
    </thead>
    <tbody>
      {rows_block}
    </tbody>
  </table>

  <script>
    const sevData = {{
      labels: ["Critical", "High", "Medium", "Low", "Info"],
      datasets: [{{
        label: "Findings",
        data: [{buckets['critical']}, {buckets['high']}, {buckets['medium']}, {buckets['low']}, {buckets['info']}],
      }}]
    }};

    const ctx = document.getElementById("severityChart").getContext("2d");
    new Chart(ctx, {{
      type: "bar",
      data: sevData,
      options: {{
        responsive: true,
        plugins: {{
          legend: {{ display: false }}
        }},
        scales: {{
          x: {{ ticks: {{ font: {{ size: 11 }} }} }},
          y: {{ beginAtZero: true, precision: 0 }}
        }}
      }}
    }});
  </script>
  <script>
    // JSON blob injected by the backend
    const reportJson = __REPORT_JSON_SENTINEL__;

    function downloadJson() {{
      const data = JSON.stringify(reportJson, null, 2);
      const blob = new Blob([data], {{ type: "application/json" }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "security_report.json";
      a.click();
      URL.revokeObjectURL(url);
    }}
  </script>
</body>
</html>
"""


def _sanitise_summary(summary: str) -> str:
    """
    Guard against SummaryAgent returning raw JSON instead of a prose narrative.

    Root cause: the old summary_agent() user content prefix said
    "Return a JSON array of enriched findings" — causing the model to echo
    the findings JSON as the summary string. Fixed in multi_agent_workflow.py
    but this sanitiser provides a defensive fallback for any edge cases.

    If summary looks like JSON (starts with [ or {), extract a readable
    fallback message rather than dumping raw JSON into the HTML card.
    """
    if not summary:
        return ""
    stripped = summary.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        # Try to extract a meaningful fallback from the JSON
        try:
            data = json.loads(stripped)
            # It's a findings array echoed back — build a brief prose fallback
            if isinstance(data, list) and data:
                n = len(data)
                crits = sum(1 for f in data if "crit" in str(f.get("severity","")).lower())
                highs = sum(1 for f in data if "high" in str(f.get("severity","")).lower())
                return (
                    f"Security scan completed. {n} finding{'s' if n != 1 else ''} identified "
                    f"({crits} critical, {highs} high). "
                    "See the findings table below for full details."
                )
        except Exception:
            pass
        # Unrecognised JSON shape — return generic message
        return "Security scan completed. See the findings table below for details."
    return summary


def render_html_report(
    summary: str,
    findings: List[Dict[str, Any]],
    lc_summary: str = "",
) -> HTMLResponse:
    """Build HTML and inject JSON for the Download JSON button."""
    # Sanitise summary before rendering — guards against raw JSON echoed by SummaryAgent
    clean_summary = _sanitise_summary(summary)

    html_doc = build_html_report_with_lc(clean_summary, findings, lc_summary=lc_summary)
    json_blob = json.dumps(
        {
            "summary": clean_summary,
            "findings": findings,
            "lc_summary": lc_summary,
        },
        indent=2,
        ensure_ascii=False,
    )
    # Sentinel token is safe to replace: not affected by f-string brace escaping
    html_doc = html_doc.replace("__REPORT_JSON_SENTINEL__", json_blob)
    return HTMLResponse(content=html_doc)

# -------------------------------------------------
# Health check
# -------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}


# -------------------------------------------------
# Analyze a single uploaded file -> JSON (basic)
# -------------------------------------------------
@app.post("/analyze-file", response_class=JSONResponse)
async def analyze_single_file(file: UploadFile = File(...)):
    """
    Upload a single source file.
    Run the basic ai_agent.analyze_file() on it and return JSON findings.
    """
    with tempfile.NamedTemporaryFile(
        delete=False, suffix=Path(_sanitise_filename(file.filename)).suffix
    ) as tmp:
        contents = await file.read()
        tmp.write(contents)
        tmp_path = Path(tmp.name)

    try:
        findings: List[Dict[str, Any]] = analyze_file(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)

    return JSONResponse(content=findings)


# -------------------------------------------------
# Analyze a ZIP -> HTML report (legacy simple HTML)
# -------------------------------------------------
@app.post("/analyze-zip-html", response_class=HTMLResponse)
async def analyze_zip_and_return_html(zip_file: UploadFile = File(...)):
    """
    Upload a ZIP containing a codebase.
    Uses the multi-agent workflow (via SupervisorAgent)
    and returns a simple HTML report based on the enriched findings.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        zip_path = tmp_dir_path / "project.zip"

        contents = await zip_file.read()
        zip_path.write_bytes(contents)

        extract_path = tmp_dir_path / "src"
        extract_path.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            try:
                _safe_extract(zf, extract_path)
            except ValueError as e:
                return HTMLResponse(
                    content=f"<h2>Upload rejected</h2><p>{html.escape(str(e))}</p>",
                    status_code=400,
                )

        findings: List[Dict[str, Any]] = (
            supervisor_result.get("result", {}).get("findings", [])
        )

    html_doc = findings_to_html(findings)
    return HTMLResponse(content=html_doc)


# -------------------------------------------------
# UI: File Scanner + Folder Scanner
# -------------------------------------------------
@app.get("/ui", response_class=HTMLResponse)
async def upload_ui():
    """
    UI with:
    - File Scanner  (single source file -> /multi-agent-file)
    - Folder Scanner (project ZIP -> /scan with Technical / Executive mode)
    """
    html_page = """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8"/>
      <title>GenAI Security Agent – UI</title>
      <style>
        body {
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #f5f7fb;
          margin: 0;
          padding: 40px;
          display: flex;
          justify-content: center;
        }
        .card {
          background: #fff;
          padding: 24px 28px;
          max-width: 720px;
          width: 100%;
          box-shadow: 0 4px 12px rgba(0,0,0,0.08);
          border-radius: 12px;
        }
        h1 { margin-top: 0; font-size: 26px; }
        h2 { font-size: 18px; margin-bottom: 4px; }
        p  { color: #555; font-size: 14px; }
        input[type="file"] { margin-top: 8px; margin-bottom: 16px; }
        input[type="text"] {
          width: 100%;
          padding: 6px 8px;
          border-radius: 6px;
          border: 1px solid #d1d5db;
          font-size: 14px;
        }
        button {
          background: #2563eb;
          border: none;
          color: #fff;
          padding: 8px 16px;
          border-radius: 6px;
          font-size: 14px;
          cursor: pointer;
        }
        button:hover { background: #1d4ed8; }
        .hint { font-size: 12px; color: #777; margin-top: 4px; }
        .section {
          margin-top: 24px;
          padding-top: 16px;
          border-top: 1px solid #e5e7eb;
        }
        .mode-group {
          margin: 12px 0 18px 0;
          padding: 10px 12px;
          background: #f3f4f6;
          border-radius: 8px;
          font-size: 14px;
        }
        .mode-option { margin-bottom: 6px; }
        .mode-label-strong { font-weight: 600; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>GenAI Security Agent</h1>
        <p>
          Choose whether you want to scan a single file or a full project, then
          select the type of security report you want.
        </p>

        <!-- ================= File Scanner ================= -->
        <div class="section">
          <h2>File Scanner (single source file)</h2>
          <p>
            Upload a single <code>.py</code>, <code>.js</code>, <code>.cs</code>, etc.
            The service runs the multi-agent workflow on that file and returns
            a structured HTML security report.
          </p>
          <form method="post" action="/multi-agent-file" enctype="multipart/form-data">
            <label for="single_file">Source file:</label><br/>
            <input type="file" id="single_file" name="file"
                   accept=".py,.js,.ts,.cs,.java,.go,.rb,.php,.c,.cpp" required />
            <div class="hint">
              Best for quick analysis of a single file.
            </div>
            <br/>
            <button type="submit">Run File Scan</button>
          </form>
        </div>

        <!-- ================= Folder Scanner ================= -->
        <div class="section">
          <h2>Folder Scanner (project ZIP)</h2>
          <p>
            Upload your codebase ZIP and choose the type of security report you want.
          </p>

          <form method="post" action="/scan" enctype="multipart/form-data">
            <label for="user_request">Instruction:</label><br/>
            <input type="text" id="user_request" name="user_request"
                   value="Please perform a full security scan on this project." />
            <br/><br/>

            <div class="mode-group">
              <div class="mode-option">
                <label>
                  <input type="radio" name="mode" value="technical" checked />
                  <span class="mode-label-strong">Technical Scan (with Guardrails)</span>
                  – detailed findings for developers and engineers.
                </label>
              </div>
              <div class="mode-option">
                <label>
                  <input type="radio" name="mode" value="executive" />
                  <span class="mode-label-strong">Executive Report (Powered by LangChain)</span>
                  – business-friendly narrative for managers and auditors.
                </label>
              </div>
            </div>

            <label for="zip_file">ZIP file:</label><br/>
            <input type="file" id="zip_file" name="zip_file" accept=".zip" required />
            <div class="hint">
              Upload a .zip containing your project's <code>src</code> / <code>app</code> folder.
            </div>
            <br/>
            <button type="submit">Run Folder Scan</button>
          </form>
        </div>

      </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_page)


# -------------------------------------------------
# Folder Scanner backend (/scan)
# -------------------------------------------------
@app.post("/scan", response_class=HTMLResponse)
async def unified_scan(
    mode: str = Form("technical"),
    user_request: str = Form("Please perform a full security scan on this project."),
    zip_file: UploadFile = File(...),
):
    """
    Folder Scanner:
    - mode = "technical"  -> Python Supervisor + guardrails
    - mode = "executive" -> LangChain Supervisor + technical findings
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        zip_path = tmp_dir_path / "project.zip"

        contents = await zip_file.read()
        zip_path.write_bytes(contents)

        extract_path = tmp_dir_path / "src"
        extract_path.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            try:
                _safe_extract(zf, extract_path)
            except ValueError as e:
                return HTMLResponse(
                    content=f"<h2>Upload rejected</h2><p>{html.escape(str(e))}</p>",
                    status_code=400,
                )

        if mode == "executive":
            lc_result = run_langchain_supervisor(extract_path, user_request)
            final_report_text = lc_result.get("final_report", "")

            base_result = run_workflow_with_supervisor(
                extract_path,
                user_request="Please perform a full security scan on this project.",
            )
            inner = base_result.get("result", {}) or {}
            summary = inner.get("summary", "")
            findings = inner.get("findings", [])
            return render_html_report(summary, findings, lc_summary=final_report_text)
        else:
            base_result = run_workflow_with_supervisor(extract_path, user_request)
            inner = base_result.get("result", {}) or {}
            summary = inner.get("summary", "")
            findings = inner.get("findings", [])
            return render_html_report(summary, findings, lc_summary="")


# -------------------------------------------------
# Multi-agent SINGLE FILE -> HTML (nice report)
# -------------------------------------------------
@app.post("/multi-agent-file", response_class=HTMLResponse)
async def multi_agent_single_file(file: UploadFile = File(...)):
    """
    Upload a single source file.
    The service wraps it in a temp folder and runs the multi-agent workflow:
      ScanAgent -> RiskClassifierAgent -> SummaryAgent

    Returns a pretty HTML report (same style as folder scan).
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir_path = Path(tmp_dir)

        tmp_file_path = tmp_dir_path / _sanitise_filename(file.filename)
        contents = await file.read()
        tmp_file_path.write_bytes(contents)

        result = run_multi_agent_workflow(tmp_dir_path)

    summary = result.get("summary", "") or ""
    findings: List[Dict[str, Any]] = result.get("findings", []) or []

    return render_html_report(summary, findings, lc_summary="")


# -------------------------------------------------
# Multi-agent SINGLE FILE -> JSON (debug)
# -------------------------------------------------
@app.post("/multi-agent-file-json", response_class=JSONResponse)
async def multi_agent_single_file_json(file: UploadFile = File(...)):
    """
    Same as /multi-agent-file but returns raw JSON.
    Useful for debugging or automation.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        tmp_file_path = tmp_dir_path / _sanitise_filename(file.filename)
        contents = await file.read()
        tmp_file_path.write_bytes(contents)

        result = run_multi_agent_workflow(tmp_dir_path)

    return JSONResponse(content=result)


# -------------------------------------------------
# Classic SupervisorAgent ZIP -> HTML
# -------------------------------------------------
@app.post("/supervisor-zip", response_class=HTMLResponse)
async def supervisor_zip(
    user_request: str = Form("Please run a security scan of this codebase."),
    zip_file: UploadFile = File(...),
):
    """
    Upload a ZIP and a high-level instruction.
    Runs the Python-based SupervisorAgent (with guardrails + multi-agent)
    and returns a business-friendly HTML report.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        zip_path = tmp_dir_path / "project.zip"

        contents = await zip_file.read()
        zip_path.write_bytes(contents)

        extract_path = tmp_dir_path / "src"
        extract_path.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            try:
                _safe_extract(zf, extract_path)
            except ValueError as e:
                return HTMLResponse(
                    content=f"<h2>Upload rejected</h2><p>{html.escape(str(e))}</p>",
                    status_code=400,
                )

        result = run_workflow_with_supervisor(extract_path, user_request)

    inner = result.get("result", {}) or {}
    summary = inner.get("summary", "")
    findings: List[Dict[str, Any]] = inner.get("findings", [])

    return render_html_report(summary, findings, lc_summary="")


# -------------------------------------------------
# LangChain SupervisorAgent ZIP -> HTML
# -------------------------------------------------
@app.post("/lc-supervisor-zip", response_class=HTMLResponse)
async def lc_supervisor_zip(
    user_request: str = Form(...),
    zip_file: UploadFile = File(...),
):
    """
    LangChain-based Supervisor Agent endpoint.

    - Extracts the uploaded ZIP into a temp folder
    - Calls run_langchain_supervisor(project_path, user_request) to get
      an executive summary written by the LangChain supervisor.
    - Also runs the standard supervisor workflow to get structured findings.
    - Returns a combined HTML report (table + executive summary).
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        zip_path = tmp_dir_path / "project.zip"

        contents = await zip_file.read()
        zip_path.write_bytes(contents)

        extract_path = tmp_dir_path / "src"
        extract_path.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            try:
                _safe_extract(zf, extract_path)
            except ValueError as e:
                return HTMLResponse(
                    content=f"<h2>Upload rejected</h2><p>{html.escape(str(e))}</p>",
                    status_code=400,
                )

        lc_result = run_langchain_supervisor(extract_path, user_request)
        final_report_text = lc_result.get("final_report", "")

        base_result = run_workflow_with_supervisor(
            extract_path,
            user_request="Please perform a full security scan on this project.",
        )
        inner = base_result.get("result", {}) or {}
        summary = inner.get("summary", "")
        findings = inner.get("findings", [])

    return render_html_report(summary, findings, lc_summary=final_report_text)
