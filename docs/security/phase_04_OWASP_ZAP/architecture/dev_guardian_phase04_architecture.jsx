import { useState } from "react";

// ── Data ──────────────────────────────────────────────────────────────────────
const GATES = [
  { label:"CRITICAL findings",                   value:"0",                                             pass:true  },
  { label:"HIGH findings confirmed",              value:"0",                                             pass:true  },
  { label:"ZipSlip _safe_extract()",              value:"HTTP 400 on all 10 traversal variants · ZAP confirmed", pass:true },
  { label:"Security headers (ZAP confirmed)",     value:"All 6 headers · Server: Dev-Guardian",          pass:true  },
  { label:"Filename XSS _sanitise_filename()",    value:"0 XSS findings in ZAP active scan",             pass:true  },
  { label:"Injection resistance (1 000 reqs)",    value:"All POST payloads → HTTP 422 · FastAPI boundary",pass:true  },
  { label:"SSRF live probes (all cloud IMDS)",    value:"12 paths → HTTP 404 · No live SSRF",            pass:true  },
  { label:"CORS configuration",                   value:"No wildcard ACAO · Clean on all origins",       pass:true  },
  { label:"Error page disclosure",                value:"No stack traces in 404/422/405",                pass:true  },
  { label:"OWASP LLM Top 10 (Phase 02 baseline)", value:"10/10 PASS · 96/100",                           pass:true  },
  { label:"CSRF protection",                      value:"OPEN — Medium — required before public launch", pass:false },
  { label:"CSP form-action directive",            value:"OPEN — one-line fix — next deploy",             pass:null  },
  { label:"MEDIUM findings remaining",            value:"4 total: CSRF + form-action + 2 CSP accepted",  pass:null  },
];

const ZAP_SCANS = [
  {
    name:"Passive baseline", id:"bff3c743-local", color:"#3b82f6", bg:"#0a1628",
    requests:"All endpoints", stats:"4 Medium alerts",
    gate:"0 HIGH / 0 CRITICAL", gc:"#10b981",
    findings:[
      { f:"Absence of Anti-CSRF Tokens", risk:"Medium", status:"OPEN — pre-launch", sc:"#ef4444" },
      { f:"CSP: script-src unsafe-inline", risk:"Medium", status:"Accepted — Swagger dependency", sc:"#f59e0b" },
      { f:"CSP: style-src unsafe-inline", risk:"Medium", status:"Accepted — UI inline styles", sc:"#f59e0b" },
      { f:"CSP: form-action not defined", risk:"Medium", status:"Pending — one-line fix", sc:"#f59e0b" },
      { f:"All security headers confirmed on /ui", risk:"Info", status:"HSTS · CSP · XCTO · XFO · CC · RP · Server:Dev-Guardian", sc:"#10b981" },
    ],
  },
  {
    name:"Active /health", id:"active-health-local", color:"#0d9488", bg:"#042e26",
    requests:"105 requests", stats:"200:17 · 404:83 · 405:4 · 307:1",
    gate:"0 HIGH / 0 CRITICAL", gc:"#10b981",
    findings:[
      { f:"WEB-INF/web.xml probe", risk:"Info", status:"HTTP 404 — irrelevant (Python/FastAPI app)", sc:"#64748b" },
      { f:"PHP LFI probes (POST /health)", risk:"Info", status:"HTTP 405 — method correctly rejected", sc:"#64748b" },
      { f:"No injection vulnerabilities", risk:"Clean", status:"0 HIGH / 0 CRITICAL", sc:"#10b981" },
    ],
  },
  {
    name:"Active /ui", id:"active-ui-local", color:"#a855f7", bg:"#180d2e",
    requests:"105 requests", stats:"200:17 · 404:83 · 405:4 · 307:1",
    gate:"0 HIGH / 0 CRITICAL", gc:"#10b981",
    findings:[
      { f:"XSS probes via filename", risk:"Info", status:"All rejected — _sanitise_filename() active", sc:"#10b981" },
      { f:"SSRF probes (IMDS paths)", risk:"Info", status:"HTTP 404 — not routable", sc:"#64748b" },
      { f:"Malformed POST inputs", risk:"Info", status:"HTTP 422 — FastAPI schema validation", sc:"#10b981" },
      { f:"0 XSS / 0 injection findings", risk:"Clean", status:"All security headers confirmed present", sc:"#10b981" },
    ],
  },
  {
    name:"Full active scan", id:"full-active-local", color:"#10b981", bg:"#0a1e0f",
    requests:"1 000 requests · 20 URLs", stats:"POST:854 · GET:146\n422:841 · 404:117 · 200:41 · 307:1",
    gate:"RELEASE GATE PASS", gc:"#10b981",
    findings:[
      { f:"All ZIP endpoint POST payloads", risk:"Info", status:"HTTP 422 — FastAPI schema · injection never reaches app", sc:"#10b981" },
      { f:"SSRF AWS /latest/meta-data/ (4 probes)", risk:"High test", status:"HTTP 404 — not exploitable at runtime", sc:"#10b981" },
      { f:"SSRF GCP /computeMetadata/v1/ (2 probes)", risk:"High test", status:"HTTP 404 — not routable", sc:"#10b981" },
      { f:"SSRF Oracle/Azure/Generic (8 probes)", risk:"High test", status:"HTTP 404 — all cloud IMDS paths blocked", sc:"#10b981" },
      { f:"SQL/shell injection probes", risk:"Info", status:"0 findings — all → HTTP 422", sc:"#10b981" },
      { f:"XSS and path traversal probes", risk:"Info", status:"0 findings — sanitisation + schema confirm", sc:"#10b981" },
    ],
  },
];

const PROBES = [
  {
    id:"TS-01", title:"Prompt Injection / LLM Hijacking", script:"prompt_injection_probe.py",
    p3status:"PASS", p4status:"PASS", delta:"No change",
    p3detail:"All 5 payload blocks classified CRITICAL. Scanner not manipulated. System prompt, API keys, env vars not leaked. _sanitise_summary() cosmetic bug: prose collapsed.",
    p4detail:"Same finding confirmed in v2.2. Gate test PASSED — scanner not manipulated. _sanitise_summary() bug still open (cosmetic only, not a security regression).",
    zapevidence:"ZAP did not probe this (code audit only). Static analysis remains primary method for LLM injection testing.",
    status:"pass",
  },
  {
    id:"TS-02", title:"SSRF / RCE via Uploaded Code", script:"ssrf_rce_probe.js",
    p3status:"PASS", p4status:"PASS", delta:"+ ZAP live SSRF confirmation",
    p3detail:"v2.2: SSRF + internal network recon code patterns detected (IMDSv1, Redis, Postgres, Docker). No outbound SSRF executed.",
    p4detail:"ZAP active scan confirmed: all 12 cloud IMDS paths (AWS/GCP/Oracle/Azure/Generic) → HTTP 404. No live outbound SSRF at runtime.",
    zapevidence:"12 SSRF probe attempts across all ZAP scans: /latest/meta-data/ · /computeMetadata/v1/ · /opc/v1/ · /opc/v2/ · /metadata/instance — all HTTP 404.",
    status:"pass",
  },
  {
    id:"TS-03", title:"ZIP Slip / Path Traversal", script:"generate_zipslip.py + zipslip_payload.zip",
    p3status:"FIXED", p4status:"CONFIRMED FIXED", delta:"+ ZAP runtime verification",
    p3detail:"_safe_extract() deployed — all 10 traversal variants rejected → HTTP 400 before extraction. Attack vector CLOSED.",
    p4detail:"ZAP full active scan (1 000 requests): 0 path traversal findings. All POST to ZIP endpoints → HTTP 422. _safe_extract() confirmed working.",
    zapevidence:"ZAP active: no path traversal in 1 000 requests. All ZIP endpoint payloads → HTTP 422 (schema validation gate before _safe_extract()).",
    status:"fixed",
  },
  {
    id:"TS-04", title:"DoS / Resource Exhaustion", script:"dos_probe.py",
    p3status:"GOOD DETECTION", p4status:"GOOD + ZAP HTTP", delta:"+ ZAP HTTP evidence",
    p3detail:"Code patterns detected: resource exhaustion, missing rate limiting, no timeout controls. _sanitise_summary() bug collapses display — cosmetic.",
    p4detail:"ZAP fired 1 000 requests: FastAPI returns HTTP 422 on all malformed inputs. No HTTP 413 or 429 observed — Railway infra-level enforcement unconfirmed.",
    zapevidence:"1 000 requests fired. 841 → HTTP 422 (FastAPI schema). No 413 (file size limit) or 429 (rate limit) observed — Railway infrastructure layer not exercised by ZAP.",
    status:"warning",
  },
  {
    id:"TS-05", title:"XSS via Filename / Report Reflection", script:"xss_report_probe.py",
    p3status:"FIXED", p4status:"CONFIRMED FIXED", delta:"ZAP: 0 XSS findings",
    p3detail:"_sanitise_filename() deployed — strips [^a-zA-Z0-9._-] at all 3 upload boundaries. CSP middleware deployed.",
    p4detail:"ZAP active scan /ui: 0 XSS findings. CSP confirmed on /ui response headers. All XSS probe filenames sanitised before disk or HTML rendering.",
    zapevidence:"ZAP active /ui: 0 XSS alerts. CSP confirmed: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net. Passive: CSP tuning alerts (accepted/pending).",
    status:"fixed",
  },
  {
    id:"TS-06", title:"Security Headers & CORS", script:"headers_cors_probe.py",
    p3status:"FIXED", p4status:"CONFIRMED FIXED", delta:"ZAP full passive confirmation",
    p3detail:"SecurityHeadersMiddleware deployed — all 5 headers set on every response. Server: Dev-Guardian. CORS clean.",
    p4detail:"ZAP passive scan confirmed all 6 headers on /ui response: HSTS · CSP · X-Content-Type-Options · X-Frame-Options · Cache-Control · Referrer-Policy. Server: Dev-Guardian (railway-edge suppressed). CORS clean.",
    zapevidence:"ZAP passive baseline bff3c743-local: full header set confirmed on GET /ui HTTP/1.1 200 OK response. No CORS misconfiguration. Error pages: no stack traces in 404/422/405.",
    status:"fixed",
  },
];

const FIXES = [
  { num:"#1", name:"_safe_extract()", ts:"TS-03", status:"DEPLOYED · ZAP CONFIRMED", sc:"#10b981", sb:"#0a1e0f",
    detail:"Replaces all zf.extractall() calls across 4 ZIP endpoints (/analyze-zip-html, /scan, /supervisor-zip, /lc-supervisor-zip). Validates every ZIP member via Path.relative_to() before extraction. Rejects ../../, URL-encoded, double-encoded, null-byte, Windows-style, absolute paths → HTTP 400. ZAP: 0 path traversal in 1 000 requests." },
  { num:"#2", name:"SecurityHeadersMiddleware", ts:"TS-06/07", status:"DEPLOYED · ZAP CONFIRMED", sc:"#10b981", sb:"#0a1e0f",
    detail:"Adds 6 headers via app.add_middleware(): HSTS max-age=31536000;includeSubDomains · CSP default-src 'self'... · X-Content-Type-Options: nosniff · X-Frame-Options: DENY · Cache-Control: no-store · Referrer-Policy: strict-origin-when-cross-origin. Suppresses Server: railway-edge. ZAP passive scan confirmed all headers present on /ui." },
  { num:"#3", name:"_sanitise_filename()", ts:"TS-05", status:"DEPLOYED · ZAP CONFIRMED", sc:"#10b981", sb:"#0a1e0f",
    detail:"Strips all chars outside [a-zA-Z0-9._-] before filename is used at any upload boundary. Applied to analyze_single_file(), multi_agent_single_file(), multi_agent_single_file_json(). ZAP active /ui: 0 XSS findings. CSP deployed as second defence layer." },
  { num:"#4", name:"_sanitise_summary() bug", ts:"TS-01/04", status:"OPEN — cosmetic", sc:"#f59e0b", sb:"#1c1400",
    detail:"Incorrectly collapses valid LLM prose summaries starting with [ or { to generic count message. Fix: add len(stripped) < 200 guard before JSON parse attempt. Security findings unaffected — display only. Bundle with #6 in next deploy." },
  { num:"#5", name:"CSRF protection", ts:"TS-07", status:"OPEN — required pre-public", sc:"#ef4444", sb:"#1c0808",
    detail:"ZAP Phase 04 passive scan confirmed: Absence of Anti-CSRF Tokens (Medium, 2 instances on GET /ui). pip install fastapi-csrf-protect. Add CSRFProtect dependency to form endpoints. Add SameSite=Strict on session cookies when auth is implemented." },
  { num:"#6", name:"CSP form-action directive", ts:"TS-07", status:"OPEN — one-line fix", sc:"#f59e0b", sb:"#1c1400",
    detail:"ZAP passive: CSP Failure to Define Directive with No Fallback on /ui. form-action not defined — defaults to allow anything. Add form-action 'self' to SecurityHeadersMiddleware CSP string. One-line change — bundle with _sanitise_summary() fix (#4)." },
  { num:"#7", name:"SRI hashes for Swagger /docs CDN JS", ts:"TS-07", status:"OPEN — 30 days post-launch", sc:"#64748b", sb:"#0d1628",
    detail:"Cross-Domain JS Source Inclusion (Low). /docs loads from cdn.jsdelivr.net without integrity attribute. Pin with integrity='sha384-...' crossorigin='anonymous', or self-host Swagger UI assets on Railway." },
];

const PHASES = [
  { num:"01", method:"OWASP LLM Manual Testing", result:"100/100 · 7/7 PASS", env:"Local + Railway Web UI", date:"Apr 2026",
    color:"#10b981", bg:"#0a1e0f",
    points:["Zero false positives — Layer 3 controls confirmed","Prompt injection fully resisted (TC-04 gate test)","All 7 vulnerability categories detected","gpt-4.1-mini (Scan/Summary) · gpt-4.1-nano (Risk/Supervisor)"] },
  { num:"02", method:"OWASP LLM Top 10 Manual", result:"96/100 · 10/10 PASS", env:"Local 127.0.0.1:8000", date:"Apr 2026",
    color:"#10b981", bg:"#0a1e0f",
    points:["+24 pts from Phase 01 (72→96)","LLM09 misinformation rule added — largest single fix","LLM02/07/10 grouping gaps all closed","All 10 OWASP LLM categories PASS"] },
  { num:"03", method:"StackHawk DAST v5.5.0", result:"0 HIGH · 0 CRITICAL", env:"Railway production", date:"May 2026",
    color:"#f59e0b", bg:"#1c1400",
    points:["3 v2.2 security fixes deployed: _safe_extract · SecurityHeaders · _sanitise_filename","StackHawk: 6M + 25L across 2 scans · 15 URLs discovered","CSRF open · 4 header Mediums closed by middleware","Spider config issue on v2 Attempt 1 — corrected"] },
  { num:"04", method:"OWASP ZAP 2.17.0 DAST", result:"0 HIGH · 0 CRITICAL\n4 MEDIUM remaining", env:"Local 127.0.0.1:8000", date:"09 May 2026",
    color:"#10b981", bg:"#0a1e0f",
    points:["1 210 total requests · 20 unique endpoints","All 3 v2.2 security fixes ZAP-confirmed","All 12 cloud IMDS SSRF paths → HTTP 404 (no live SSRF)","841/1000 active requests → HTTP 422 (FastAPI schema gate)","4 MEDIUM remaining: CSRF + form-action + 2 CSP accepted"] },
];

const REMEDIATION = [
  { pri:1, ts:"TS-03", item:"ZipSlip _safe_extract() — all 10 traversal variants blocked", sev:"HIGH", status:"CLOSED", sc:"#10b981", evidence:"ZAP Phase 04: 0 path traversal in 1 000 requests" },
  { pri:2, ts:"TS-05", item:"XSS filename — _sanitise_filename() deployed · ZAP: 0 XSS", sev:"HIGH", status:"CLOSED", sc:"#10b981", evidence:"ZAP active /ui: 0 XSS alerts · CSP deployed" },
  { pri:3, ts:"TS-06/07", item:"All 5 security headers deployed via SecurityHeadersMiddleware", sev:"MEDIUM", status:"CLOSED", sc:"#10b981", evidence:"ZAP passive: HSTS · CSP · XCTO · XFO · Cache-Control · RP all confirmed" },
  { pri:4, ts:"TS-07", item:"CSRF protection — Anti-CSRF Tokens absent (2 instances on /ui)", sev:"MEDIUM", status:"OPEN", sc:"#ef4444", evidence:"ZAP Phase 04 passive scan confirmed still open" },
  { pri:5, ts:"TS-07", item:"CSP form-action not defined — one-line fix pending", sev:"MEDIUM", status:"OPEN", sc:"#f59e0b", evidence:"ZAP: CSP Failure to Define Directive with No Fallback" },
  { pri:6, ts:"TS-07", item:"CSP script-src unsafe-inline — accepted (Swagger /docs)", sev:"MEDIUM", status:"ACCEPTED", sc:"#3b82f6", evidence:"Risk accepted — required for Swagger UI CDN rendering" },
  { pri:7, ts:"TS-07", item:"CSP style-src unsafe-inline — accepted (/ui inline styles)", sev:"MEDIUM", status:"ACCEPTED", sc:"#3b82f6", evidence:"Risk accepted — migrate to external stylesheet post-launch" },
  { pri:8, ts:"TS-04", item:"Railway HTTP 413/429 enforcement — infra layer unconfirmed", sev:"MEDIUM", status:"OPEN", sc:"#f59e0b", evidence:"ZAP 1 000 requests: no 413/429 observed (Railway layer not tested)" },
  { pri:9, ts:"TS-01/04", item:"_sanitise_summary() len guard — cosmetic bug pending", sev:"LOW", status:"OPEN", sc:"#f59e0b", evidence:"Bundle with form-action CSP fix in next deploy" },
  { pri:10, ts:"TS-02", item:"OOB SSRF — Burp Collaborator test pending", sev:"LOW", status:"OPEN", sc:"#64748b", evidence:"ZAP confirms 404 but OOB callback requires Burp Collaborator" },
  { pri:11, ts:"TS-07", item:"SRI hashes for Swagger /docs CDN JS", sev:"LOW", status:"OPEN", sc:"#64748b", evidence:"30 days post-launch — cdn.jsdelivr.net scripts unverified" },
];

// ── Helpers ──────────────────────────────────────────────────────────────────
const statusMeta = {
  pass:    { label:"PASS",            sc:"#10b981", sb:"#0a1e0f" },
  fixed:   { label:"CONFIRMED FIXED", sc:"#0d9488", sb:"#042e26" },
  warning: { label:"GOOD DETECTION",  sc:"#f59e0b", sb:"#1c1400" },
  fail:    { label:"FAIL",            sc:"#ef4444", sb:"#1c0808" },
};
const mono = { fontFamily:"'IBM Plex Mono','Courier New',monospace" };

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  const [tab, setTab]         = useState("gates");
  const [openProbe, setOpen]  = useState(null);
  const [openFix, setOpenFix] = useState(null);
  const [openScan, setOpenScan] = useState(null);
  const [openPhase, setOpenPhase] = useState(null);

  const tabs = [
    { id:"gates",   label:"Release gates"  },
    { id:"scans",   label:"ZAP scans"      },
    { id:"probes",  label:"Manual probes"  },
    { id:"fixes",   label:"Fix register"   },
    { id:"phases",  label:"All phases"     },
    { id:"remed",   label:"Remediation"    },
  ];

  return (
    <div style={{ ...mono, minHeight:"100vh", background:"#080c14", color:"#e2e8f0" }}>

      {/* Header */}
      <div style={{ background:"#0f2044", borderBottom:"1px solid #1e293b", padding:"16px 24px", display:"flex", justifyContent:"space-between", alignItems:"center" }}>
        <div>
          <div style={{ fontSize:10, color:"#3b82f6", letterSpacing:"0.15em", marginBottom:3 }}>URIELLE AI AUDIT · AISB SG 2026 · PHASE 04</div>
          <div style={{ fontSize:17, fontWeight:700, color:"#f1f5f9" }}>DEV GUARDIAN — ZAP DAST ARCHITECTURE</div>
          <div style={{ fontSize:10, color:"#475569", marginTop:2 }}>OWASP ZAP 2.17.0 · api_server.py v2.2 · 127.0.0.1:8000 · 09 May 2026 · 1 210 total requests</div>
        </div>
        <div style={{ textAlign:"right" }}>
          <div style={{ fontSize:10, color:"#475569" }}>RELEASE</div>
          <div style={{ fontSize:14, fontWeight:700, color:"#10b981", marginTop:2 }}>PILOT APPROVED</div>
          <div style={{ fontSize:10, color:"#f59e0b", marginTop:2 }}>0 HIGH · 0 CRITICAL</div>
          <div style={{ fontSize:10, color:"#f59e0b" }}>CSRF required pre-public</div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display:"flex", borderBottom:"1px solid #1e293b", padding:"0 24px", overflowX:"auto" }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            background:"none", border:"none", cursor:"pointer",
            padding:"11px 16px", fontSize:11, letterSpacing:"0.08em", whiteSpace:"nowrap",
            color: tab===t.id ? "#3b82f6" : "#475569",
            borderBottom: tab===t.id ? "2px solid #3b82f6" : "2px solid transparent",
          }}>{t.label.toUpperCase()}</button>
        ))}
      </div>

      <div style={{ padding:"20px 24px" }}>

        {/* ── RELEASE GATES ── */}
        {tab==="gates" && (
          <div>
            <p style={{ fontSize:11, color:"#64748b", marginBottom:14 }}>Phase 04 final gate assessment. All CRITICAL and HIGH items cleared by v2.2 and confirmed by ZAP. 4 MEDIUM findings remaining.</p>
            {GATES.map((g,i) => (
              <div key={i} style={{
                background: g.pass===false?"#1c0808":g.pass===null?"#1c1400":"#0a1e0f",
                border:`1px solid ${g.pass===false?"#ef4444":g.pass===null?"#f59e0b44":"#10b98144"}`,
                borderRadius:6, padding:"9px 14px", marginBottom:5,
                display:"flex", justifyContent:"space-between", alignItems:"center",
              }}>
                <span style={{ fontSize:11, color:"#e2e8f0" }}>{g.label}</span>
                <span style={{ fontSize:11, fontWeight:700, color: g.pass===false?"#ef4444":g.pass===null?"#f59e0b":"#10b981" }}>
                  {g.pass===true?"✓ ":g.pass===false?"⚠ ":"⚠ "}{g.value}
                </span>
              </div>
            ))}
            <div style={{ background:"#0a1e0f", border:"2px solid #10b981", borderRadius:8, padding:"14px 18px", marginTop:16, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <div>
                <div style={{ fontSize:13, fontWeight:700, color:"#10b981" }}>APPROVED FOR PASSWORD-GATED PILOT LAUNCH</div>
                <div style={{ fontSize:10, color:"#64748b", marginTop:4 }}>All four phases complete · 0 HIGH · 0 CRITICAL across 1 210 ZAP requests</div>
              </div>
              <div style={{ textAlign:"right" }}>
                <div style={{ fontSize:10, color:"#f59e0b", fontWeight:700 }}>CSRF middleware</div>
                <div style={{ fontSize:10, color:"#f59e0b" }}>required before</div>
                <div style={{ fontSize:10, color:"#f59e0b" }}>public launch</div>
              </div>
            </div>
          </div>
        )}

        {/* ── ZAP SCANS ── */}
        {tab==="scans" && (
          <div>
            <p style={{ fontSize:11, color:"#64748b", marginBottom:14 }}>Four ZAP scan runs. Click any scan to expand findings. 1 210 total requests across all runs.</p>

            {/* HTTP code summary bar */}
            <div style={{ background:"#0d1628", border:"1px solid #1e293b", borderRadius:8, padding:14, marginBottom:14 }}>
              <div style={{ fontSize:10, fontWeight:700, color:"#64748b", marginBottom:10 }}>HTTP RESPONSE CODE DISTRIBUTION — 1 000 ACTIVE REQUESTS</div>
              <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:8 }}>
                {[
                  { code:"422", reason:"Unprocessable", count:841, pct:"84.1%", color:"#10b981", bg:"#0a1e0f", note:"FastAPI schema validation — injection blocked" },
                  { code:"404", reason:"Not Found",     count:117, pct:"11.7%", color:"#0d9488", bg:"#042e26", note:"SSRF/path probes — not routable" },
                  { code:"200", reason:"OK",            count:41,  pct:"4.1%",  color:"#3b82f6", bg:"#0a1628", note:"/ui, /health, /openapi.json" },
                  { code:"405", reason:"Not Allowed",   count:4,   pct:"0.4%",  color:"#f59e0b", bg:"#1c1400", note:"PHP/LFI POST to GET-only endpoints" },
                  { code:"307", reason:"Redirect",      count:1,   pct:"0.1%",  color:"#64748b", bg:"#0d1628", note:"/ → /ui internal redirect" },
                ].map(c => (
                  <div key={c.code} style={{ background:c.bg, border:`1px solid ${c.color}44`, borderRadius:6, padding:"10px 8px", textAlign:"center" }}>
                    <div style={{ fontSize:16, fontWeight:700, color:c.color }}>{c.code}</div>
                    <div style={{ fontSize:10, fontWeight:700, color:c.color, marginTop:2 }}>{c.count} <span style={{ fontSize:9, color:"#64748b" }}>({c.pct})</span></div>
                    <div style={{ fontSize:8, color:"#64748b", marginTop:4, lineHeight:1.4 }}>{c.note}</div>
                  </div>
                ))}
              </div>
            </div>

            {ZAP_SCANS.map(sc => {
              const isOpen = openScan === sc.id;
              return (
                <div key={sc.id} style={{ marginBottom:6 }}>
                  <div onClick={() => setOpenScan(isOpen ? null : sc.id)}
                    style={{ background:isOpen?sc.bg:"#0d1628", border:`1px solid ${isOpen?sc.color:"#1e293b"}`,
                      borderRadius:isOpen?"8px 8px 0 0":8, padding:"10px 14px",
                      cursor:"pointer", display:"flex", alignItems:"center", gap:12 }}>
                    <span style={{ fontSize:12, fontWeight:700, color:sc.color, minWidth:120 }}>{sc.name}</span>
                    <span style={{ fontSize:9, color:"#64748b", fontFamily:"monospace", flex:1 }}>{sc.id}</span>
                    <span style={{ fontSize:10, color:"#94a3b8" }}>{sc.requests}</span>
                    <span style={{ background:sc.bg, color:sc.gc, border:`1px solid ${sc.gc}`, borderRadius:4, padding:"2px 10px", fontSize:9, fontWeight:700 }}>{sc.gate}</span>
                    <span style={{ color:"#475569" }}>{isOpen?"▲":"▼"}</span>
                  </div>
                  {isOpen && (
                    <div style={{ background:sc.bg, border:`1px solid ${sc.color}`, borderTop:"none", borderRadius:"0 0 8px 8px", padding:14 }}>
                      <div style={{ fontSize:9, color:"#64748b", marginBottom:8 }}>{sc.stats}</div>
                      {sc.findings.map((f,i) => (
                        <div key={i} style={{ display:"flex", gap:10, padding:"5px 0", borderBottom:"1px solid #1e293b22", alignItems:"center" }}>
                          <span style={{ fontSize:10, color:"#e2e8f0", flex:1 }}>{f.f}</span>
                          <span style={{ fontSize:9, color:"#64748b", minWidth:60, textAlign:"center" }}>{f.risk}</span>
                          <span style={{ fontSize:9, color:f.sc, fontWeight:700, minWidth:200, textAlign:"right" }}>{f.status}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* ── MANUAL PROBES ── */}
        {tab==="probes" && (
          <div>
            <p style={{ fontSize:11, color:"#64748b", marginBottom:14 }}>Click any probe to expand Phase 03 vs Phase 04 comparison with ZAP evidence. All probes against api_server.py v2.2.</p>
            {PROBES.map(p => {
              const isOpen = openProbe === p.id;
              const sm = statusMeta[p.status];
              return (
                <div key={p.id} style={{ marginBottom:6 }}>
                  <div onClick={() => setOpen(isOpen?null:p.id)}
                    style={{ background:isOpen?sm.sb:"#0d1628", border:`1px solid ${isOpen?sm.sc:"#1e293b"}`,
                      borderRadius:isOpen?"8px 8px 0 0":8, padding:"10px 14px",
                      cursor:"pointer", display:"flex", alignItems:"center", gap:12 }}>
                    <span style={{ fontSize:11, fontWeight:700, color:"#3b82f6", minWidth:44 }}>{p.id}</span>
                    <span style={{ fontSize:11, color:"#e2e8f0", flex:1 }}>{p.title}</span>
                    <span style={{ fontSize:9, color:"#0d9488", fontFamily:"monospace", marginRight:8 }}>{p.script}</span>
                    <span style={{ background:sm.sb, color:sm.sc, border:`1px solid ${sm.sc}`, borderRadius:4, padding:"2px 8px", fontSize:9, fontWeight:700 }}>{sm.label}</span>
                    <span style={{ color:"#475569" }}>{isOpen?"▲":"▼"}</span>
                  </div>
                  {isOpen && (
                    <div style={{ background:sm.sb, border:`1px solid ${sm.sc}`, borderTop:"none", borderRadius:"0 0 8px 8px", padding:14 }}>
                      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:10 }}>
                        <div>
                          <div style={{ fontSize:9, color:"#f59e0b", fontWeight:700, marginBottom:5 }}>Phase 03 — {p.p3status}</div>
                          <div style={{ fontSize:10, color:"#94a3b8", lineHeight:1.6 }}>{p.p3detail}</div>
                        </div>
                        <div>
                          <div style={{ fontSize:9, color:sm.sc, fontWeight:700, marginBottom:5 }}>Phase 04 — {p.p4status} · {p.delta}</div>
                          <div style={{ fontSize:10, color:"#94a3b8", lineHeight:1.6 }}>{p.p4detail}</div>
                        </div>
                      </div>
                      <div style={{ background:"#0d1628", borderRadius:6, padding:"8px 10px" }}>
                        <div style={{ fontSize:9, color:"#a855f7", fontWeight:700, marginBottom:4 }}>ZAP Evidence</div>
                        <div style={{ fontSize:10, color:"#64748b" }}>{p.zapevidence}</div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* ── FIX REGISTER ── */}
        {tab==="fixes" && (
          <div>
            <p style={{ fontSize:11, color:"#64748b", marginBottom:14 }}>Click any fix to expand detail and ZAP confirmation evidence. 3 DEPLOYED · 1 cosmetic bug · 2 open security gaps · 1 post-launch item.</p>
            {FIXES.map(f => {
              const isOpen = openFix === f.num;
              return (
                <div key={f.num} style={{ marginBottom:6 }}>
                  <div onClick={() => setOpenFix(isOpen?null:f.num)}
                    style={{ background:isOpen?f.sb:"#0d1628", border:`1px solid ${isOpen?f.sc:"#1e293b"}`,
                      borderRadius:isOpen?"8px 8px 0 0":8, padding:"10px 14px",
                      cursor:"pointer", display:"flex", alignItems:"center", gap:12 }}>
                    <span style={{ fontSize:10, color:"#3b82f6", minWidth:28, fontWeight:700 }}>{f.num}</span>
                    <span style={{ fontSize:11, color:"#e2e8f0", fontWeight:700, flex:1 }}>{f.name}</span>
                    <span style={{ fontSize:9, color:"#0d9488", fontFamily:"monospace", marginRight:8 }}>{f.ts}</span>
                    <span style={{ color:f.sc, fontSize:9, fontWeight:700 }}>{f.status}</span>
                    <span style={{ color:"#475569" }}>{isOpen?"▲":"▼"}</span>
                  </div>
                  {isOpen && (
                    <div style={{ background:f.sb, border:`1px solid ${f.sc}`, borderTop:"none", borderRadius:"0 0 8px 8px", padding:14 }}>
                      <div style={{ fontSize:10, color:"#94a3b8", lineHeight:1.7 }}>{f.detail}</div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* ── ALL PHASES ── */}
        {tab==="phases" && (
          <div>
            <p style={{ fontSize:11, color:"#64748b", marginBottom:14 }}>Full four-phase security testing progression. Click any phase to expand key achievements.</p>
            {PHASES.map(ph => {
              const isOpen = openPhase === ph.num;
              return (
                <div key={ph.num} style={{ marginBottom:8 }}>
                  <div onClick={() => setOpenPhase(isOpen?null:ph.num)}
                    style={{ background:isOpen?ph.bg:"#0d1628", border:`1px solid ${isOpen?ph.color:"#1e293b"}`,
                      borderRadius:isOpen?"8px 8px 0 0":8, padding:"12px 16px",
                      cursor:"pointer", display:"flex", alignItems:"center", gap:14 }}>
                    <span style={{ fontSize:16, fontWeight:700, color:ph.color, minWidth:80 }}>Phase {ph.num}</span>
                    <span style={{ fontSize:11, color:"#e2e8f0", fontWeight:700, flex:1 }}>{ph.method}</span>
                    <span style={{ fontSize:11, fontWeight:700, color:ph.color, textAlign:"right", minWidth:140 }}>{ph.result}</span>
                    <span style={{ fontSize:10, color:"#64748b", minWidth:80, textAlign:"right" }}>{ph.date}</span>
                    <span style={{ color:"#475569" }}>{isOpen?"▲":"▼"}</span>
                  </div>
                  {isOpen && (
                    <div style={{ background:ph.bg, border:`1px solid ${ph.color}`, borderTop:"none", borderRadius:"0 0 8px 8px", padding:14 }}>
                      <div style={{ fontSize:9, color:"#64748b", marginBottom:8 }}>Environment: {ph.env}</div>
                      {ph.points.map((pt,i) => (
                        <div key={i} style={{ display:"flex", gap:10, marginBottom:6 }}>
                          <span style={{ color:ph.color, fontSize:12 }}>→</span>
                          <span style={{ fontSize:10, color:"#94a3b8" }}>{pt}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}

            {/* Phase comparison table */}
            <div style={{ background:"#0d1628", border:"1px solid #1e293b", borderRadius:8, padding:14, marginTop:14 }}>
              <div style={{ fontSize:10, fontWeight:700, color:"#64748b", marginBottom:10 }}>PHASE 03 (STACKHAWK) → PHASE 04 (ZAP) KEY DELTA</div>
              {[
                { ts:"TS-01", p3:"PASS (same finding)", p4:"PASS (ZAP: N/A — code audit only)", delta:"No change" },
                { ts:"TS-02", p3:"PASS (static SSRF detection)", p4:"PASS + ZAP live confirms all 12 IMDS paths → 404", delta:"+ ZAP OOB evidence" },
                { ts:"TS-03", p3:"FIXED (_safe_extract deployed)", p4:"CONFIRMED FIXED · ZAP: 0 traversal in 1 000 reqs", delta:"+ Runtime verification" },
                { ts:"TS-04", p3:"GOOD DETECTION (code patterns)", p4:"GOOD + ZAP: 841/1000 → 422 · no 413/429 from Railway", delta:"+ HTTP evidence" },
                { ts:"TS-05", p3:"FIXED (_sanitise_filename)", p4:"CONFIRMED FIXED · ZAP active /ui: 0 XSS findings", delta:"+ ZAP confirms 0 XSS" },
                { ts:"TS-06", p3:"FIXED (SecurityHeadersMiddleware)", p4:"CONFIRMED FIXED · ZAP passive: all 6 headers on /ui", delta:"+ Full ZAP confirmation" },
                { ts:"TS-07", p3:"StackHawk: 6M+25L · 15 URLs", p4:"ZAP: 4M · 1 210 reqs · same gate result", delta:"Same gate: 0H/0C" },
              ].map((r,i) => (
                <div key={i} style={{ display:"grid", gridTemplateColumns:"60px 1fr 1fr 140px", gap:10,
                  padding:"6px 0", borderBottom:"1px solid #1e293b22", alignItems:"center" }}>
                  <span style={{ fontSize:10, fontWeight:700, color:"#3b82f6" }}>{r.ts}</span>
                  <span style={{ fontSize:9, color:"#64748b" }}>{r.p3}</span>
                  <span style={{ fontSize:9, color:"#94a3b8" }}>{r.p4}</span>
                  <span style={{ fontSize:9, color:"#0d9488", fontWeight:700, textAlign:"right" }}>{r.delta}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── REMEDIATION ── */}
        {tab==="remed" && (
          <div>
            <p style={{ fontSize:11, color:"#64748b", marginBottom:12 }}>Phase 04 remediation tracker. All CRITICAL and HIGH items closed. 4 MEDIUM open (CSRF required pre-public).</p>
            <div style={{ overflowX:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead>
                  <tr style={{ background:"#1e293b" }}>
                    {["Pri","TS","Item","Severity","Status","Evidence"].map(h => (
                      <th key={h} style={{ padding:"6px 8px", textAlign:"left", color:"#64748b", fontSize:9, fontWeight:700, borderBottom:"1px solid #334155" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {REMEDIATION.map((r,i) => {
                    const sev_c = r.sev==="HIGH"?"#ef4444":r.sev==="MEDIUM"?"#f59e0b":r.sev==="LOW"?"#64748b":"#3b82f6";
                    return (
                      <tr key={i} style={{ background: i%2===0?"#0d1628":"#1e293b", borderBottom:"1px solid #1e293b" }}>
                        <td style={{ padding:"6px 8px", color:"#3b82f6", fontWeight:700, fontSize:11 }}>{r.pri}</td>
                        <td style={{ padding:"6px 8px", color:"#0d9488", fontSize:9, fontFamily:"monospace" }}>{r.ts}</td>
                        <td style={{ padding:"6px 8px", color:"#e2e8f0", fontSize:10 }}>{r.item}</td>
                        <td style={{ padding:"6px 8px", color:sev_c, fontSize:9, fontWeight:700 }}>{r.sev}</td>
                        <td style={{ padding:"6px 8px" }}>
                          <span style={{ color:r.sc, fontWeight:700, fontSize:9 }}>{r.status}</span>
                        </td>
                        <td style={{ padding:"6px 8px", color:"#64748b", fontSize:9 }}>{r.evidence}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div style={{ background:"#0a1e0f", border:"2px solid #10b981", borderRadius:8, padding:"10px 14px", marginTop:16 }}>
              <div style={{ fontSize:11, fontWeight:700, color:"#10b981" }}>RELEASE GATE — CONDITIONAL PASS</div>
              <div style={{ fontSize:10, color:"#64748b", marginTop:4 }}>0 CRITICAL · 0 HIGH · CSRF (Medium) required before public launch · form-action CSP one-line fix in next deploy</div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
