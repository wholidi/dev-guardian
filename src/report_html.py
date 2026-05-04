# report_html.py
#
# Produces a styled standalone HTML security report from a findings list.
# Used by the CLI (ai_agent.py --html flag) and any caller that needs a
# self-contained file rather than a FastAPI HTMLResponse.
#
# Design mirrors the report produced by api_server.build_html_report_with_lc()
# so CLI output and web UI output are visually identical.

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _severity_key(sev: str) -> str:
    """Normalise raw severity string → one of: critical high medium low info."""
    s = sev.strip().lower()
    if "crit" in s: return "critical"
    if "high" in s: return "high"
    if "med"  in s: return "medium"
    if "low"  in s: return "low"
    return "info"


def _count_buckets(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = _severity_key(f.get("severity") or "")
        buckets[key] += 1
    return buckets


def _overall_risk(buckets: Dict[str, int]) -> tuple:
    """Return (label, css-class) for the overall risk badge."""
    if buckets["critical"] > 0:
        return "Critical", "risk-critical"
    if buckets["high"] >= 2 or (buckets["high"] == 1 and buckets["medium"] >= 2):
        return "High", "risk-high"
    if buckets["medium"] > 0:
        return "Medium", "risk-medium"
    if sum(buckets.values()) > 0:
        return "Low", "risk-low"
    return "None", "risk-none"


def _build_rows(findings: List[Dict[str, Any]]) -> str:
    rows: List[str] = []
    for f in findings:
        sev_key = _severity_key(f.get("severity") or "")
        sev_raw = (f.get("severity") or "info").upper()
        title       = html.escape(f.get("title")          or "")
        location    = html.escape(f.get("location")       or f.get("source_file", ""))
        description = html.escape(f.get("description")    or "")
        rec         = html.escape(f.get("recommendation") or "")
        owasp       = html.escape(f.get("owasp_category") or "")
        owasp_cell  = (
            f'<br/><span class="owasp-tag">{owasp}</span>' if owasp else ""
        )
        rows.append(f"""
        <tr>
          <td class="sev-cell severity-{sev_key}">{sev_raw}</td>
          <td>{title}{owasp_cell}</td>
          <td><code>{location}</code></td>
          <td>{description}</td>
          <td>{rec}</td>
        </tr>""")
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# CSS — single source of truth
# ---------------------------------------------------------------------------
_CSS = """
  :root {
    --navy:   #0D1B2A;
    --steel:  #1B3A5C;
    --accent: #2196F3;
    --bg:     #F5F7FB;
    --card:   #FFFFFF;
    --border: #E2E8F0;
    --text:   #1E293B;
    --muted:  #64748B;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 32px 24px;
    font-size: 14px;
    line-height: 1.5;
  }

  /* top bar */
  .topbar {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 24px;
    gap: 16px;
  }
  .topbar-left h1 { font-size: 22px; font-weight: 700; color: var(--navy); }
  .topbar-left .subtitle { color: var(--muted); font-size: 12px; margin-top: 4px; }
  .topbar-right { display: flex; gap: 8px; flex-shrink: 0; }

  /* risk badge */
  .risk-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .04em;
  }
  .risk-critical { background:#FEE2E2; color:#B91C1C; }
  .risk-high     { background:#FEF3C7; color:#92400E; }
  .risk-medium   { background:#E0F2FE; color:#075985; }
  .risk-low      { background:#DCFCE7; color:#166534; }
  .risk-none     { background:#E5E7EB; color:#374151; }

  /* cards */
  .card {
    background: var(--card);
    border-radius: 10px;
    padding: 20px 24px;
    box-shadow: 0 1px 4px rgba(15,23,42,.08);
    margin-bottom: 20px;
  }
  .card h2 {
    font-size: 13px;
    font-weight: 700;
    color: var(--navy);
    margin-bottom: 12px;
    text-transform: uppercase;
    letter-spacing: .06em;
  }

  /* stat strip */
  .stats { display: flex; gap: 12px; flex-wrap: wrap; }
  .stat {
    flex: 1 1 90px;
    padding: 12px 16px;
    border-radius: 8px;
    text-align: center;
  }
  .stat-value { font-size: 26px; font-weight: 800; }
  .stat-label { font-size: 11px; font-weight: 600; text-transform: uppercase; margin-top: 2px; }
  .stat-total    { background:#F1F5F9; color:#0F172A; }
  .stat-critical { background:#FEE2E2; color:#B91C1C; }
  .stat-high     { background:#FEF3C7; color:#92400E; }
  .stat-medium   { background:#E0F2FE; color:#075985; }
  .stat-low      { background:#DCFCE7; color:#166534; }

  /* layout */
  .layout { display: grid; grid-template-columns: 1fr 300px; gap: 20px; margin-bottom: 20px; }
  @media (max-width: 800px) { .layout { grid-template-columns: 1fr; } }
  .summary-text { font-size: 13px; color: var(--text); white-space: pre-wrap; }

  /* table */
  .tbl-wrap {
    background: var(--card);
    border-radius: 10px;
    overflow: hidden;
    box-shadow: 0 1px 4px rgba(15,23,42,.08);
    margin-bottom: 20px;
  }
  table { width: 100%; border-collapse: collapse; }
  thead th {
    background: var(--navy);
    color: #FFF;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .06em;
    padding: 11px 12px;
    text-align: left;
    white-space: nowrap;
  }
  tbody tr:nth-child(even) { background: #F8FAFC; }
  tbody tr:hover { background: #EFF6FF; }
  td {
    padding: 10px 12px;
    font-size: 13px;
    vertical-align: top;
    border-bottom: 1px solid var(--border);
  }
  tbody tr:last-child td { border-bottom: none; }
  code {
    font-family: ui-monospace, "Cascadia Code", Menlo, monospace;
    font-size: 12px;
    background: #F1F5F9;
    padding: 2px 5px;
    border-radius: 4px;
  }
  .sev-cell {
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    text-align: center;
    width: 80px;
    white-space: nowrap;
  }
  .severity-critical { background:#FEE2E2; color:#B91C1C; }
  .severity-high     { background:#FEF3C7; color:#92400E; }
  .severity-medium   { background:#E0F2FE; color:#075985; }
  .severity-low      { background:#DCFCE7; color:#166534; }
  .severity-info     { background:#E5E7EB; color:#374151; }

  .owasp-tag {
    font-size: 10px;
    font-weight: 600;
    color: var(--accent);
    background: #E8F4FD;
    padding: 1px 5px;
    border-radius: 4px;
    display: inline-block;
    margin-top: 3px;
  }

  /* buttons */
  .btn {
    border: 1px solid var(--border);
    background: var(--card);
    color: var(--text);
    padding: 7px 13px;
    border-radius: 7px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: background .15s;
  }
  .btn:hover { background: #F1F5F9; }
  .btn-primary { background: var(--accent); color: #FFF; border-color: var(--accent); }
  .btn-primary:hover { background: #1976D2; }

  /* footer */
  .footer {
    text-align: center;
    font-size: 11px;
    color: var(--muted);
    margin-top: 32px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
  }

  @media print {
    .topbar-right, .btn { display: none !important; }
    body { background: #fff; padding: 16px; }
    .card, .tbl-wrap { box-shadow: none; border: 1px solid var(--border); }
  }
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def findings_to_html(
    findings: List[Dict[str, Any]],
    summary: str = "",
    title: str = "Dev Guardian — Security Report",
) -> str:
    """
    Render findings + optional summary into a standalone HTML string.

    Args:
        findings: list of finding dicts (title, severity, location,
                  description, recommendation; owasp_category optional)
        summary:  plain-text summary from SummaryAgent (optional)
        title:    page/report title shown in the header

    Returns:
        Complete, self-contained HTML document as a string.
    """
    buckets = _count_buckets(findings)
    total = len(findings)
    risk_label, risk_class = _overall_risk(buckets)
    rows_html = _build_rows(findings)

    summary_block = ""
    if summary:
        summary_block = f"""
      <div class="card">
        <h2>Summary</h2>
        <pre class="summary-text">{html.escape(summary.strip())}</pre>
      </div>"""

    chart_data = json.dumps([
        buckets["critical"], buckets["high"],
        buckets["medium"],   buckets["low"],
        buckets["info"],
    ])

    json_blob = json.dumps(
        {"title": title, "summary": summary, "findings": findings},
        indent=2,
        ensure_ascii=False,
    )

    from datetime import datetime, timezone
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    no_findings_row = (
        '<tr><td colspan="5" style="text-align:center;padding:32px;'
        'color:#64748B;">No findings — codebase appears clean.</td></tr>'
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{html.escape(title)}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
  <style>{_CSS}</style>
</head>
<body>

  <div class="topbar">
    <div class="topbar-left">
      <h1>{html.escape(title)}</h1>
      <div class="subtitle">
        Generated {generated}
        &nbsp;|&nbsp; Overall risk:&nbsp;
        <span class="risk-badge {risk_class}">{risk_label}</span>
      </div>
    </div>
    <div class="topbar-right">
      <button class="btn" onclick="window.print()">&#8203;&#11167; Print / PDF</button>
      <button class="btn btn-primary" onclick="downloadJson()">&#11167; Download JSON</button>
    </div>
  </div>

  <div class="card">
    <div class="stats">
      <div class="stat stat-total">
        <div class="stat-value">{total}</div>
        <div class="stat-label">Total</div>
      </div>
      <div class="stat stat-critical">
        <div class="stat-value">{buckets["critical"]}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat stat-high">
        <div class="stat-value">{buckets["high"]}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat stat-medium">
        <div class="stat-value">{buckets["medium"]}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat stat-low">
        <div class="stat-value">{buckets["low"]}</div>
        <div class="stat-label">Low</div>
      </div>
    </div>
  </div>

  <div class="layout">
    <div>{summary_block}</div>
    <div class="card">
      <h2>Severity distribution</h2>
      <canvas id="sevChart" height="220"></canvas>
    </div>
  </div>

  <div class="tbl-wrap">
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
        {rows_html if rows_html else no_findings_row}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Dev Guardian &nbsp;&middot;&nbsp; Urielle AI Audit &nbsp;&middot;&nbsp; AISB Singapore 2026
  </div>

  <script>
    new Chart(document.getElementById("sevChart"), {{
      type: "bar",
      data: {{
        labels: ["Critical", "High", "Medium", "Low", "Info"],
        datasets: [{{
          data: {chart_data},
          backgroundColor: ["#FCA5A5","#FCD34D","#93C5FD","#86EFAC","#D1D5DB"],
          borderColor:     ["#B91C1C","#92400E","#075985","#166534","#374151"],
          borderWidth: 1.5,
          borderRadius: 4,
        }}]
      }},
      options: {{
        responsive: true,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{
          x: {{ ticks: {{ font: {{ size: 11 }} }} }},
          y: {{ beginAtZero: true, ticks: {{ precision: 0 }} }}
        }}
      }}
    }});

    const _reportJson = __REPORT_JSON_SENTINEL__;
    function downloadJson() {{
      const blob = new Blob(
        [JSON.stringify(_reportJson, null, 2)],
        {{ type: "application/json" }}
      );
      const a = Object.assign(document.createElement("a"), {{
        href: URL.createObjectURL(blob),
        download: "dev_guardian_report.json",
      }});
      a.click();
      URL.revokeObjectURL(a.href);
    }}
  </script>
</body>
</html>"""

    # Inject the JSON blob via sentinel — safe from f-string brace collisions
    return doc.replace("__REPORT_JSON_SENTINEL__", json_blob)


def save_html_report(
    findings: List[Dict[str, Any]],
    output_path: Path,
    summary: str = "",
    title: str = "Dev Guardian — Security Report",
) -> None:
    """
    Write a styled HTML security report to disk.

    Args:
        findings:    list of finding dicts
        output_path: destination .html file path
        summary:     optional plain-text summary from SummaryAgent
        title:       report title shown in the page header
    """
    html_doc = findings_to_html(findings, summary=summary, title=title)
    output_path.write_text(html_doc, encoding="utf-8")
    print(f"[Report] HTML saved → {output_path}  ({len(findings)} findings)")
