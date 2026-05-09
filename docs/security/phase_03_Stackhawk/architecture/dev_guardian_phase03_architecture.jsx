import { useState } from "react";

const GATES = [
  { label: "CRITICAL findings",               value: "0",                           pass: true },
  { label: "HIGH findings confirmed",          value: "0",                           pass: true },
  { label: "OWASP LLM Top 10 (Phase 02)",      value: "10/10 · 96/100",              pass: true },
  { label: "ZipSlip runtime protection",       value: "HTTP 400 on traversal",       pass: true },
  { label: "Security headers (ZAP confirmed)", value: "All 5 deployed",              pass: true },
  { label: "Filename XSS sanitisation",        value: "10/10 payloads blocked",      pass: true },
  { label: "No stack traces in error pages",   value: "4xx/5xx clean",               pass: true },
  { label: "CORS not misconfigured",           value: "No wildcard ACAO",            pass: true },
  { label: "CSRF protection",                  value: "OPEN — required pre-public",  pass: false },
  { label: "MEDIUM findings remaining",        value: "2 (CSRF + CSP — accepted)",   pass: null  },
];

const COVERAGE = [
  { vuln:"Prompt injection in code",       ref:"LLM01",     hawk:"Partial", manual:"Full",    note:"HTTP probes at instruction field only; manual embeds injection in uploaded source files" },
  { vuln:"Sensitive data / PII / secrets", ref:"LLM02",     hawk:"Partial", manual:"Full",    note:"HTTP can find secrets in responses; manual finds secrets in source and PII sent to LLM" },
  { vuln:"Supply chain / pickle RCE",      ref:"LLM03",     hawk:"None",    manual:"Full",    note:"torch.load, GPU side-channel, pickle exist purely in code logic — no HTTP trigger" },
  { vuln:"SQL / shell injection",          ref:"A03/LLM04", hawk:"Full",    manual:"Full",    note:"Highest combined confidence — both confirm live server + code pattern" },
  { vuln:"LLM output handling (exec/XSS)", ref:"LLM05",     hawk:"Partial", manual:"Full",    note:"exec(llm_output) requires reading code logic, not HTTP responses" },
  { vuln:"Excessive agency / no HITL",     ref:"LLM06",     hawk:"None",    manual:"Full",    note:"Governance risk — no HTTP signal; requires reading code for missing confirmation gates" },
  { vuln:"System prompt leakage",          ref:"LLM07",     hawk:"Partial", manual:"Full",    note:"StackHawk probes HTTP responses; manual finds credentials hardcoded in system prompt string" },
  { vuln:"RAG / vector embedding ACL",     ref:"LLM08",     hawk:"None",    manual:"Full",    note:"Namespace isolation and ACL gaps are architectural decisions invisible over HTTP" },
  { vuln:"Role misrepresentation",         ref:"LLM09",     hawk:"None",    manual:"Full",    note:"Ethics/governance risk with no HTTP signal — required Phase 02 rule addition" },
  { vuln:"Rate limiting / max_tokens",     ref:"LLM10/API4",hawk:"Full",    manual:"Full",    note:"Both confirm — StackHawk checks 429/413 live; manual confirms missing max_tokens in code" },
  { vuln:"ZIP Slip / path traversal",      ref:"A01",       hawk:"Full",    manual:"None",    note:"Runtime extraction behavior — requires live server to confirm traversal blocked" },
  { vuln:"Security headers / CORS",        ref:"A05",       hawk:"Full",    manual:"None",    note:"HTTP response properties — invisible in uploaded source code" },
  { vuln:"XSS via report filename",        ref:"A03",       hawk:"Full",    manual:"None",    note:"Live HTTP behavior — server must encode filename output; undetectable from code files" },
  { vuln:"SSRF (live OOB confirmation)",   ref:"A10",       hawk:"Full",    manual:"Partial", note:"Manual embeds SSRF in code; only DAST can confirm server makes outbound request" },
];

const PROBES = [
  { id:"TS-01", title:"Prompt Injection / LLM Hijacking",   script:"prompt_injection_probe.py",
    v21:"PASS", v22:"PASS", delta:"No change",
    v21detail:"All 5 payload blocks (instruction override, DAN, SSRF, SSTI, data exfil) classified CRITICAL. Scanner not manipulated. System prompt, API keys, env vars not leaked.",
    v22detail:"Finding identical in substance. Summary collapsed to generic count due to _sanitise_summary() bug in v2.2 — cosmetic only, not a security regression.",
    status:"pass" },
  { id:"TS-02", title:"SSRF / RCE via Uploaded Code",        script:"ssrf_rce_probe.js",
    v21:"PASS", v22:"PASS", delta:"Different LLM angle",
    v21detail:"v2.1: prompt injection suppression attempt in comments detected (Stop analysing, Do not flag vulnerabilities). No SSRF execution.",
    v22detail:"v2.2: SSRF + internal network recon code patterns detected (IMDSv1, Redis, Postgres, Docker). Both are correct perspectives on same dual-risk file.",
    status:"pass" },
  { id:"TS-03", title:"ZIP Slip / Path Traversal",            script:"generate_zipslip.py + zipslip_payload.zip",
    v21:"PARTIAL", v22:"FIXED", delta:"PARTIAL → PASS",
    v21detail:"Analysed extracted code only. Found hardcoded credentials + weak crypto in main.py/utils.py. Did NOT flag ZIP traversal entry names (../../, URL-encoded, null-byte, Windows-style).",
    v22detail:"_safe_extract() added — all 10 traversal variants rejected before extraction. HTTP 400 returned. Attack vector CLOSED. Confirmed by ZAP re-scan.",
    status:"fixed" },
  { id:"TS-04", title:"DoS / Resource Exhaustion",            script:"dos_probe.py",
    v21:"GOOD", v22:"KNOWN BUG", delta:"Display degraded",
    v21detail:"Correctly identified: resource exhaustion risk, missing rate limiting, no timeout controls, no anomaly logging. Full key_issues and quick_wins returned.",
    v22detail:"1 finding, source_file only — no detail in findings array. Summary collapsed to generic count by _sanitise_summary() bug. Security finding still present — display only.",
    status:"warning" },
  { id:"TS-05", title:"XSS via Filename / Report Reflection", script:"xss_report_probe.py",
    v21:"HIGH (static)", v22:"FIXED", delta:"HIGH → PASS",
    v21detail:"Static analysis flagged IMPORTANT FINDING: Potential Reflected/Stored XSS via Uploaded Filename. Live HTTP probe: HTTP 404 on /scan/file — endpoint path mismatch.",
    v22detail:"_sanitise_filename() deployed — strips [^a-zA-Z0-9._-] at all 3 upload boundaries. All 10 XSS filename payloads blocked. CSP middleware deployed. Manual Burp confirmation pending.",
    status:"fixed" },
  { id:"TS-06", title:"Security Headers & CORS",              script:"headers_cors_probe.py",
    v21:"OPEN", v22:"FIXED", delta:"5 headers → all present",
    v21detail:"5 headers MISSING across all endpoints: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Cache-Control. Server: railway-edge disclosed. CORS clean (no wildcard ACAO).",
    v22detail:"SecurityHeadersMiddleware deployed. All 5 headers confirmed by ZAP active + passive scan. Server now returns Dev-Guardian. CORS clean confirmed.",
    status:"fixed" },
];

const SCANS = [
  { name:"Hawk v1.1",        id:"4e4e3a96", urls:13, finding:"6 Medium + 18 Low · No HIGH/CRITICAL",       gate:"BASELINE",   gc:"#3b82f6" },
  { name:"Hawk v2 Attempt 1",id:"be31407d", urls:2,  finding:"Spider config issue — only robots.txt/sitemap discovered. Discarded.",gate:"CONFIG FIX",C:"#f59e0b",gc:"#f59e0b" },
  { name:"Hawk v2 Corrected",id:"fa11b19c", urls:15, finding:"6M + 25L · 0 HIGH / 0 CRITICAL · Full 15-URL scan via openApiConf + seedPaths", gate:"GATE PASS", gc:"#10b981" },
  { name:"OWASP ZAP 2.17.0", id:"bff3c743", urls:"all", finding:"0 HIGH · 0 CRITICAL · All 5 security headers confirmed · Final confirmation scan", gate:"CONFIRMED", gc:"#10b981" },
];

const FIXES = [
  { num:"#1", name:"_safe_extract()", ts:"TS-03", status:"DEPLOYED", sc:"#10b981", sb:"#0a1e0f",
    detail:"Replaces all zf.extractall() calls across 4 ZIP endpoints. Validates every ZIP member via Path.relative_to() before extraction. Rejects ../../, URL-encoded, double-encoded, null-byte, Windows-style, absolute paths → HTTP 400." },
  { num:"#2", name:"SecurityHeadersMiddleware", ts:"TS-06/07", status:"DEPLOYED", sc:"#10b981", sb:"#0a1e0f",
    detail:"Adds 6 headers to every response via app.add_middleware(): HSTS max-age=31536000, CSP default-src self, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Cache-Control: no-store, Referrer-Policy. Suppresses Server: railway-edge." },
  { num:"#3", name:"_sanitise_filename()", ts:"TS-05", status:"DEPLOYED", sc:"#10b981", sb:"#0a1e0f",
    detail:"Strips all chars outside [a-zA-Z0-9._-] before filename is used at any upload boundary. Applied to analyze_single_file(), multi_agent_single_file(), multi_agent_single_file_json()." },
  { num:"#4", name:"_sanitise_summary() bug", ts:"TS-01/04", status:"OPEN — cosmetic", sc:"#f59e0b", sb:"#1c1400",
    detail:"Incorrectly collapses valid LLM prose summaries starting with [ or { into generic count message. Fix: add len(stripped) < 200 guard before JSON parse attempt. Security findings unaffected — display only." },
  { num:"#5", name:"CSRF protection", ts:"TS-07", status:"OPEN — required pre-launch", sc:"#ef4444", sb:"#1c0808",
    detail:"pip install fastapi-csrf-protect. Add CSRFProtect dependency to form endpoints. Add SameSite=Strict on session cookies when auth is implemented. Priority increases pre-public launch." },
  { num:"#6", name:"SRI hashes — Swagger /docs CDN JS", ts:"TS-07", status:"OPEN — 30 days post-launch", sc:"#64748b", sb:"#0d1628",
    detail:"Cross-Domain JS Source Inclusion (Low). Pin cdn.jsdelivr.net scripts with integrity='sha384-...' crossorigin='anonymous', or self-host Swagger UI assets on Railway." },
];

const LLM_PROG = [
  { id:"LLM01", cat:"Prompt Injection",         p1:"PASS 5/4",    p2:"PASS 6/4",    delta:"+1", fix:"Separate-finding rule + COMPLETENESS RULES block + MAX_TOKENS 1500→4000" },
  { id:"LLM02", cat:"Sensitive Info Disclosure", p1:"PARTIAL 4/5", p2:"PASS 10/5",   delta:"+6", fix:"PCI/PII logging rule + Credential Separation Rule + Payment Data Patterns added" },
  { id:"LLM03", cat:"Supply Chain / Pickle RCE", p1:"PASS 8/4",    p2:"PASS 8/4",    delta:"=",  fix:"Stable — __pycache__ clear procedure established to prevent stale bytecode" },
  { id:"LLM04", cat:"Data & Model Poisoning",    p1:"PASS 2/2",    p2:"PASS 2/2",    delta:"=",  fix:"JSON export sentinel token fix in api_server.py" },
  { id:"LLM05", cat:"Improper Output Handling",  p1:"PASS 3/3",    p2:"PASS 3/3",    delta:"=",  fix:"Stable — no fix required" },
  { id:"LLM06", cat:"Excessive Agency",          p1:"PASS 2/2",    p2:"PASS 2/2",    delta:"=",  fix:"Stable — AISB Day 7 alignment confirmed" },
  { id:"LLM07", cat:"System Prompt Leakage",     p1:"PARTIAL 1/3", p2:"PASS 4/3",    delta:"+3", fix:"LLM07 non-merge rule + RISK_CLASSIFIER_PROMPT updated to prevent grouping" },
  { id:"LLM08", cat:"Vector & Embedding",        p1:"PASS 3/2",    p2:"PASS 3/2",    delta:"=",  fix:"Stable — no fix required" },
  { id:"LLM09", cat:"Misinformation",            p1:"FAIL 0/2",    p2:"PASS 3/2",    delta:"+3", fix:"Role Misrepresentation rule added — largest single Phase 02 improvement" },
  { id:"LLM10", cat:"Unbounded Consumption",     p1:"PARTIAL 1/3", p2:"PASS 3/3",    delta:"+2", fix:"Unbounded Consumption rule — max_tokens and rate limit patterns now flagged" },
  { id:"—",     cat:"TOTAL",                     p1:"72/100",      p2:"96/100",       delta:"+24",fix:"All 10 OWASP LLM categories PASS" },
];

const statusColor = { pass:"#10b981", fixed:"#0d9488", warning:"#f59e0b", fail:"#ef4444" };
const statusBg    = { pass:"#0a1e0f", fixed:"#042e26", warning:"#1c1400", fail:"#1c0808" };
const statusLabel = { pass:"PASS", fixed:"FIXED", warning:"KNOWN BUG", fail:"FAIL" };

const covColor = (v) =>
  v==="Full"    ? "#10b981" :
  v==="Partial" ? "#f59e0b" :
  v==="None"    ? "#475569" : "#e2e8f0";

export default function App() {
  const [tab, setTab]       = useState("gates");
  const [open, setOpen]     = useState(null);
  const [openFix, setOpenFix] = useState(null);
  const [openLlm, setOpenLlm] = useState(null);

  const tabs = [
    { id:"gates",    label:"Release gates" },
    { id:"coverage", label:"Coverage map" },
    { id:"probes",   label:"Manual probes" },
    { id:"dast",     label:"DAST scans" },
    { id:"fixes",    label:"Fix register" },
    { id:"llm",      label:"LLM progression" },
  ];

  const mono = { fontFamily:"'IBM Plex Mono','Courier New',monospace" };

  return (
    <div style={{ ...mono, minHeight:"100vh", background:"#080c14", color:"#e2e8f0" }}>
      {/* Header */}
      <div style={{ background:"#0f2044", borderBottom:"1px solid #1e293b", padding:"16px 24px", display:"flex", justifyContent:"space-between", alignItems:"center" }}>
        <div>
          <div style={{ fontSize:10, color:"#3b82f6", letterSpacing:"0.15em", marginBottom:3 }}>URIELLE AI AUDIT · AISB SG 2026 · PHASE 03</div>
          <div style={{ fontSize:17, fontWeight:700, color:"#f1f5f9" }}>DEV GUARDIAN — DAST & PRE-RELEASE SECURITY</div>
          <div style={{ fontSize:10, color:"#475569", marginTop:2 }}>StackHawk v5.5.0 + OWASP ZAP 2.17.0 · api_server.py v2.2 · May 2026</div>
        </div>
        <div style={{ textAlign:"right" }}>
          <div style={{ fontSize:10, color:"#475569" }}>RELEASE DECISION</div>
          <div style={{ fontSize:16, fontWeight:700, color:"#10b981", marginTop:2 }}>PILOT APPROVED</div>
          <div style={{ fontSize:10, color:"#f59e0b", marginTop:2 }}>CSRF required pre-public</div>
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
            <p style={{ fontSize:11, color:"#64748b", marginBottom:14 }}>Pre-release security gate checklist. All CRITICAL and HIGH gates cleared. Pilot launch approved with CSRF as outstanding pre-public requirement.</p>
            {GATES.map((g,i) => (
              <div key={i} style={{ background: g.pass===false ? "#1c0808" : g.pass===null ? "#1c1400" : "#0a1e0f",
                border:`1px solid ${g.pass===false?"#ef4444":g.pass===null?"#f59e0b":"#10b981"}`,
                borderRadius:6, padding:"10px 14px", marginBottom:6,
                display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                <span style={{ fontSize:11, color:"#e2e8f0" }}>{g.label}</span>
                <span style={{ fontSize:11, fontWeight:700,
                  color: g.pass===false?"#ef4444":g.pass===null?"#f59e0b":"#10b981" }}>
                  {g.pass===false?"⚠ ":g.pass===null?"⚠ ":"✓ "}{g.value}
                </span>
              </div>
            ))}
            <div style={{ background:"#0a1e0f", border:"2px solid #10b981", borderRadius:8, padding:"14px 18px", marginTop:16, textAlign:"center" }}>
              <div style={{ fontSize:13, fontWeight:700, color:"#10b981" }}>APPROVED FOR PASSWORD-GATED PILOT LAUNCH</div>
              <div style={{ fontSize:10, color:"#f59e0b", marginTop:6 }}>CSRF middleware must be implemented before removing the password gate and opening to the public.</div>
            </div>
          </div>
        )}

        {/* ── COVERAGE MAP ── */}
        {tab==="coverage" && (
          <div>
            <p style={{ fontSize:11, color:"#64748b", marginBottom:10 }}>Two-method testing: StackHawk DAST (black-box HTTP attacker) + OWASP LLM manual testing (white-box code auditor). Neither method can replicate the other.</p>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8, marginBottom:16 }}>
              {[
                { title:"StackHawk DAST", color:"#3b82f6", bg:"#0a1628", items:["ZIP Slip at extraction runtime","Security headers / CORS","XSS via report filename reflection","HTTP 413 / 429 enforcement","SSRF (OOB callback confirmation)","Stack trace in error pages"] },
                { title:"OWASP LLM Manual Testing", color:"#a855f7", bg:"#180d2e", items:["Pickle RCE / GPU side-channel (LLM03)","Excessive agency / no HITL (LLM06)","RAG namespace / ACL gaps (LLM08)","Role misrepresentation (LLM09)","System prompt credential exposure (LLM07)","PII / card data to external LLM (LLM02)","exec(llm_output) / os.system(llm) (LLM05)"] },
              ].map((m,i) => (
                <div key={i} style={{ background:m.bg, border:`1px solid ${m.color}44`, borderRadius:8, padding:12 }}>
                  <div style={{ fontSize:10, fontWeight:700, color:m.color, marginBottom:8 }}>UNIQUE TO: {m.title}</div>
                  {m.items.map((item,j) => (
                    <div key={j} style={{ display:"flex", gap:8, marginBottom:4 }}>
                      <span style={{ color:m.color, fontSize:11 }}>→</span>
                      <span style={{ fontSize:10, color:"#94a3b8" }}>{item}</span>
                    </div>
                  ))}
                </div>
              ))}
            </div>
            <div style={{ overflowX:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse", fontSize:10 }}>
                <thead>
                  <tr style={{ background:"#1e293b" }}>
                    {["Vulnerability","OWASP Ref","StackHawk","Manual Testing","Key Insight"].map(h => (
                      <th key={h} style={{ padding:"6px 8px", textAlign:"left", color:"#64748b", fontWeight:700, fontSize:9, borderBottom:"1px solid #334155" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {COVERAGE.map((r,i) => (
                    <tr key={i} style={{ background: i%2===0 ? "#0d1628" : "#1e293b" }}>
                      <td style={{ padding:"5px 8px", color:"#e2e8f0" }}>{r.vuln}</td>
                      <td style={{ padding:"5px 8px", color:"#3b82f6", fontWeight:700, textAlign:"center" }}>{r.ref}</td>
                      <td style={{ padding:"5px 8px", color:covColor(r.hawk), fontWeight:700, textAlign:"center" }}>{r.hawk}</td>
                      <td style={{ padding:"5px 8px", color:covColor(r.manual), fontWeight:700, textAlign:"center" }}>{r.manual}</td>
                      <td style={{ padding:"5px 8px", color:"#64748b", fontSize:9 }}>{r.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── MANUAL PROBES ── */}
        {tab==="probes" && (
          <div>
            <p style={{ fontSize:11, color:"#64748b", marginBottom:14 }}>Click any probe to expand v2.1 vs v2.2 results. All probes run against api_server.py v2.1 (pre-fix) and v2.2 (post-fix).</p>
            {PROBES.map(p => {
              const isOpen = open === p.id;
              const sc = statusColor[p.status]; const sb = statusBg[p.status];
              return (
                <div key={p.id} style={{ marginBottom:6 }}>
                  <div onClick={() => setOpen(isOpen ? null : p.id)}
                    style={{ background: isOpen ? sb : "#0d1628", border:`1px solid ${isOpen?sc:"#1e293b"}`,
                      borderRadius: isOpen?"8px 8px 0 0":8, padding:"10px 14px",
                      cursor:"pointer", display:"flex", alignItems:"center", gap:12 }}>
                    <span style={{ fontSize:11, fontWeight:700, color:"#3b82f6", minWidth:44 }}>{p.id}</span>
                    <span style={{ fontSize:11, color:"#e2e8f0", flex:1 }}>{p.title}</span>
                    <span style={{ fontSize:9, color:"#64748b", fontFamily:"monospace", marginRight:8 }}>{p.script}</span>
                    <span style={{ background:sb, color:sc, border:`1px solid ${sc}`, borderRadius:4,
                      padding:"2px 8px", fontSize:9, fontWeight:700 }}>{statusLabel[p.status]}</span>
                    <span style={{ color:"#475569" }}>{isOpen?"▲":"▼"}</span>
                  </div>
                  {isOpen && (
                    <div style={{ background:sb, border:`1px solid ${sc}`, borderTop:"none",
                      borderRadius:"0 0 8px 8px", padding:14 }}>
                      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
                        <div>
                          <div style={{ fontSize:9, color:"#f59e0b", fontWeight:700, marginBottom:6 }}>v2.1 · {p.v21}</div>
                          <div style={{ fontSize:10, color:"#94a3b8", lineHeight:1.6 }}>{p.v21detail}</div>
                        </div>
                        <div>
                          <div style={{ fontSize:9, color:sc, fontWeight:700, marginBottom:6 }}>v2.2 · {p.v22} · {p.delta}</div>
                          <div style={{ fontSize:10, color:"#94a3b8", lineHeight:1.6 }}>{p.v22detail}</div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* ── DAST SCANS ── */}
        {tab==="dast" && (
          <div>
            <p style={{ fontSize:11, color:"#64748b", marginBottom:14 }}>StackHawk v5.5.0 automated DAST + OWASP ZAP 2.17.0 final confirmation. Three scan runs total — one discarded due to spider config issue.</p>
            {SCANS.map((sc,i) => (
              <div key={i} style={{ background:"#0d1628", border:`1px solid ${sc.gc}44`, borderRadius:8, padding:14, marginBottom:8 }}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
                  <div>
                    <span style={{ fontSize:12, fontWeight:700, color:sc.gc }}>{sc.name}</span>
                    <span style={{ fontSize:9, color:"#64748b", marginLeft:10, fontFamily:"monospace" }}>{sc.id}</span>
                  </div>
                  <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                    <span style={{ fontSize:10, color:"#94a3b8" }}>{sc.urls} URLs</span>
                    <span style={{ background:"#0d1628", color:sc.gc, border:`1px solid ${sc.gc}`, borderRadius:4,
                      padding:"2px 10px", fontSize:9, fontWeight:700 }}>{sc.gate}</span>
                  </div>
                </div>
                <div style={{ fontSize:10, color:"#94a3b8" }}>{sc.finding}</div>
              </div>
            ))}
            <div style={{ background:"#0a1e0f", border:"1px solid #10b98133", borderRadius:8, padding:14, marginTop:4 }}>
              <div style={{ fontSize:10, fontWeight:700, color:"#10b981", marginBottom:8 }}>ZAP FINAL SCAN — FINDING SUMMARY (api_server.py v2.2, local)</div>
              {[
                { f:"Absence of Anti-CSRF Tokens",        risk:"Medium", conf:"Low",  status:"OPEN — required before public launch",    sc:"#ef4444" },
                { f:"CSP: script-src unsafe-inline",       risk:"Medium", conf:"High", status:"Accepted — required for Swagger /docs",    sc:"#f59e0b" },
                { f:"CSP: style-src unsafe-inline",        risk:"Medium", conf:"High", status:"Accepted — required for /ui inline styles", sc:"#f59e0b" },
                { f:"CSP: form-action not defined",        risk:"Medium", conf:"High", status:"Pending — add form-action self (1-line)",   sc:"#f59e0b" },
                { f:"Cross-Domain JS Source Inclusion",    risk:"Low",    conf:"—",    status:"Open — SRI hashes, 30 days post-launch",    sc:"#64748b" },
                { f:"HIGH findings",                       risk:"—",      conf:"—",    status:"0 — gate CLEAN",                            sc:"#10b981" },
                { f:"CRITICAL findings",                   risk:"—",      conf:"—",    status:"0 — gate CLEAN",                            sc:"#10b981" },
              ].map((r,j) => (
                <div key={j} style={{ display:"flex", gap:10, padding:"5px 0", borderBottom:"1px solid #1e293b", alignItems:"center" }}>
                  <span style={{ fontSize:10, color:"#e2e8f0", flex:1 }}>{r.f}</span>
                  <span style={{ fontSize:9, color:"#64748b", minWidth:50, textAlign:"center" }}>{r.risk}</span>
                  <span style={{ fontSize:9, color:r.sc, fontWeight:700, minWidth:200, textAlign:"right" }}>{r.status}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── FIX REGISTER ── */}
        {tab==="fixes" && (
          <div>
            <p style={{ fontSize:11, color:"#64748b", marginBottom:14 }}>Click any fix to expand code detail. Three security fixes deployed in v2.2. One cosmetic bug. Two items pending.</p>
            {FIXES.map(f => {
              const isOpen = openFix === f.num;
              return (
                <div key={f.num} style={{ marginBottom:6 }}>
                  <div onClick={() => setOpenFix(isOpen ? null : f.num)}
                    style={{ background: isOpen ? f.sb : "#0d1628", border:`1px solid ${isOpen?f.sc:"#1e293b"}`,
                      borderRadius: isOpen?"8px 8px 0 0":8, padding:"10px 14px",
                      cursor:"pointer", display:"flex", alignItems:"center", gap:12 }}>
                    <span style={{ fontSize:10, color:"#3b82f6", minWidth:24 }}>{f.num}</span>
                    <span style={{ fontSize:11, color:"#e2e8f0", fontWeight:700, flex:1 }}>{f.name}</span>
                    <span style={{ fontSize:9, color:"#0d9488", fontFamily:"monospace", marginRight:8 }}>{f.ts}</span>
                    <span style={{ color:f.sc, fontSize:9, fontWeight:700 }}>{f.status}</span>
                    <span style={{ color:"#475569" }}>{isOpen?"▲":"▼"}</span>
                  </div>
                  {isOpen && (
                    <div style={{ background:f.sb, border:`1px solid ${f.sc}`, borderTop:"none",
                      borderRadius:"0 0 8px 8px", padding:14 }}>
                      <div style={{ fontSize:10, color:"#94a3b8", lineHeight:1.6 }}>{f.detail}</div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* ── LLM PROGRESSION ── */}
        {tab==="llm" && (
          <div>
            <p style={{ fontSize:11, color:"#64748b", marginBottom:12 }}>Phase 01 → Phase 02 improvements. Click a row for fix detail. +24 points total — 72/100 → 96/100.</p>
            <div style={{ overflowX:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead>
                  <tr style={{ background:"#1e293b" }}>
                    {["ID","Category","Phase 01","Phase 02","Delta","Key Fix Applied"].map(h => (
                      <th key={h} style={{ padding:"7px 8px", textAlign:"left", color:"#64748b",
                        fontSize:9, fontWeight:700, borderBottom:"1px solid #334155" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {LLM_PROG.map((r,i) => {
                    const isOpen = openLlm === r.id;
                    const p1c = r.p1.includes("FAIL") ? "#ef4444" : r.p1.includes("PARTIAL") ? "#f59e0b" : "#10b981";
                    const dc  = r.delta.includes("+") ? "#10b981" : "#64748b";
                    const isTotal = r.cat==="TOTAL";
                    return (
                      <tr key={i}
                        onClick={() => setOpenLlm(isOpen ? null : r.id)}
                        style={{ background: isTotal ? "#0a1e0f" : i%2===0 ? "#0d1628" : "#1e293b",
                          cursor:"pointer", borderBottom: isTotal ? "2px solid #10b981" : "1px solid #1e293b" }}>
                        <td style={{ padding:"6px 8px", color:"#3b82f6", fontWeight:700 }}>{r.id}</td>
                        <td style={{ padding:"6px 8px", color: isTotal ? "#10b981" : "#e2e8f0", fontWeight: isTotal ? 700 : 400 }}>{r.cat}</td>
                        <td style={{ padding:"6px 8px", color:p1c, fontWeight:700, textAlign:"center" }}>{r.p1}</td>
                        <td style={{ padding:"6px 8px", color:"#10b981", fontWeight:700, textAlign:"center" }}>{r.p2}</td>
                        <td style={{ padding:"6px 8px", color:dc, fontWeight:700, textAlign:"center" }}>{r.delta}</td>
                        <td style={{ padding:"6px 8px", color: isOpen ? "#e2e8f0" : "#64748b", fontSize:10 }}>{r.fix}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
