from pathlib import Path
import json
import html
from typing import List, Dict, Any


def findings_to_html(findings: List[Dict[str, Any]]) -> str:
    def esc(x: Any) -> str:
        return html.escape("" if x is None else str(x))

    rows = []
    for f in findings:
        sev = (f.get("severity") or "").upper()
        title = f.get("title") or ""
        location = f.get("location") or f.get("source_file") or ""
        desc = f.get("description") or ""
        rec = f.get("recommendation") or ""

        sev_class = "SEV-" + sev if sev else ""
        rows.append(
            f"""
            <tr class="{sev_class}">
              <td class="severity">{esc(sev)}</td>
              <td class="title">{esc(title)}</td>
              <td class="location">{esc(location)}</td>
              <td class="description">{esc(desc)}</td>
              <td class="recommendation">{esc(rec)}</td>
            </tr>
            """
        )

    total = len(findings)

    html_doc = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>AI Security Findings</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 24px;
      background: #f5f7fb;
      color: #222;
    }}
    h1 {{
      margin-bottom: 0;
    }}
    .meta {{
      margin-top: 4px;
      color: #555;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
      margin-top: 16px;
      background: #fff;
      box-shadow: 0 2px 6px rgba(0,0,0,0.06);
    }}
    th, td {{
      border: 1px solid #e0e3ec;
      padding: 8px 10px;
      vertical-align: top;
      font-size: 14px;
    }}
    th {{
      background: #f0f2f8;
      text-align: left;
    }}
    tr:nth-child(even) td {{
      background: #fafbff;
    }}
    .severity {{
      font-weight: bold;
      white-space: nowrap;
    }}
    .SEV-HIGH .severity {{
      background: #ffe0e0;
      color: #b30000;
    }}
    .SEV-CRITICAL .severity {{
      background: #ffb3b3;
      color: #7f0000;
    }}
    .SEV-MEDIUM .severity {{
      background: #fff4d6;
      color: #915c00;
    }}
    .SEV-LOW .severity {{
      background: #e3f5ff;
      color: #004b80;
    }}
    .location {{
      font-family: "Cascadia Code", "Consolas", monospace;
      font-size: 12px;
      color: #555;
    }}
  </style>
</head>
<body>
  <h1>AI Security Findings</h1>
  <div class="meta">Total findings: {total}</div>

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
      {''.join(rows) if rows else '<tr><td colspan="5">No findings.</td></tr>'}
    </tbody>
  </table>
</body>
</html>
"""
    return html_doc


def save_html_report(findings: List[Dict[str, Any]], out_path: Path) -> Path:
    html_doc = findings_to_html(findings)
    out_path.write_text(html_doc, encoding="utf-8")
    return out_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate HTML report from findings JSON"
    )
    parser.add_argument(
        "input_json", help="Path to findings.json (list of findings)"
    )
    parser.add_argument(
        "output_html", nargs="?", default="security_report.html",
        help="Output HTML path (default: security_report.html)"
    )
    args = parser.parse_args()

    in_path = Path(args.input_json)
    out_path = Path(args.output_html)

    data = json.loads(in_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit("Expected JSON array at top level.")

    save_html_report(data, out_path)
    print(f"Saved HTML report to {out_path}")
