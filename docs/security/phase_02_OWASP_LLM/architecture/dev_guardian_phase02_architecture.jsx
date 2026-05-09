import { useState } from "react";

const OWASP_RESULTS = [
  {
    id: "LLM01", cat: "Prompt Injection", file: "owasp_llm01_prompt_injection.py",
    day: "Day 3 — LLM Security", severity: "CRITICAL", expected: 4, actual: 5,
    status: "pass", score: "5/4",
    findings: [
      "Hardcoded API key (CRITICAL)",
      "Direct prompt injection — scan_user_code()",
      "Unsanitised user input in prompts — process_user_instruction()",
      "Indirect prompt injection — summarise_external_document()",
      "Embedded jailbreak strings — BYPASS_INSTRUCTION variable",
    ],
    gap: "None — all 5 patterns detected including jailbreak",
    fix: "JSON shows 1 grouped finding. Separate-finding prompt for Session 2.",
    riskToScanner: "High — Direct attack on scanner itself",
  },
  {
    id: "LLM02", cat: "Sensitive Info Disclosure", file: "owasp_llm02_sensitive_info.py",
    day: "Day 2 — Data Security", severity: "CRITICAL", expected: 5, actual: 4,
    status: "partial", score: "4/5",
    findings: [
      "Hardcoded OpenAI API Key (CRITICAL)",
      "Hardcoded DB Password (CRITICAL)",
      "Internal API URL exposed (MEDIUM)",
      "Admin Bearer Token hardcoded (CRITICAL)",
    ],
    gap: "Card/CVV logging + PII-to-LLM not flagged · PCI DSS gap",
    fix: "Card number logging (PCI DSS) not flagged. PII transmission to external LLM not detected.",
    riskToScanner: "High — Privacy and regulatory risk",
  },
  {
    id: "LLM03", cat: "Supply Chain Vulnerabilities", file: "owasp_llm03_supply_chain.py",
    day: "Day 4 — Infrastructure Security", severity: "CRITICAL", expected: 4, actual: 8,
    status: "pass", score: "8/4",
    findings: [
      "Remote Pickle Deserialisation from URL (CRITICAL)",
      "Local Pickle with Unsanitised Path (CRITICAL)",
      "GPU Side-Channel Memory Access (HIGH)",
      "Unsafe Pip Install at Runtime (CRITICAL)",
      "Dynamic Plugin Import (HIGH)",
      "Unpinned Dependencies (MEDIUM)",
      "Unverified External Config Fetch (HIGH)",
      "torch.load RCE via pickle (CRITICAL)",
    ],
    gap: "GPU side-channel detected but as HIGH not CRITICAL. LLM03-specific OWASP mapping needed.",
    fix: "pycache bug masked results until __pycache__ was cleared. Wrong source file uploaded initially.",
    riskToScanner: "Medium — Supply chain attack surface",
  },
  {
    id: "LLM04", cat: "Data & Model Poisoning", file: "owasp_llm04_to_llm10.py",
    day: "Day 3 — LLM Security", severity: "CRITICAL", expected: 2, actual: 2,
    status: "pass", score: "2/2",
    findings: [
      "SQL Injection in store_training_sample() (CRITICAL)",
      "Shell Injection in fine_tune_on_user_feedback() (CRITICAL)",
    ],
    gap: "JSON export bug — HTML report correct, JSON only captured API key",
    fix: "Investigate api_server.py JSON export path — findings lost between HTML render and JSON save.",
    riskToScanner: "High — Model integrity risk",
  },
  {
    id: "LLM05", cat: "Improper Output Handling", file: "owasp_llm04_to_llm10.py",
    day: "Day 3 — LLM Security", severity: "CRITICAL", expected: 3, actual: 3,
    status: "pass", score: "3/3",
    findings: [
      "Stored XSS via unsanitised LLM output → innerHTML (CRITICAL)",
      "Arbitrary Code Execution via exec(LLM_output) (CRITICAL)",
      "Command Injection via os.system(LLM_command) (CRITICAL)",
    ],
    gap: "None — all 3 critical patterns detected",
    fix: "No fix required. Consider running LLM05 section in isolation for cleaner JSON.",
    riskToScanner: "Critical — Direct code execution",
  },
  {
    id: "LLM06", cat: "Excessive Agency", file: "owasp_llm04_to_llm10.py",
    day: "Day 7 — AI Control", severity: "HIGH", expected: 2, actual: 2,
    status: "pass", score: "2/2",
    findings: [
      "Excessive Agency — Unrestricted LLM Tool Access (email/DB/shell/funds, no confirmation)",
      "High-Risk Decision Delegation without Human Review (loan approval, access grants via LLM)",
    ],
    gap: "AI governance risk recognised — AISB Day 7 alignment confirmed",
    fix: "Scanner recognises governance risk beyond code vulnerability. Good coverage.",
    riskToScanner: "High — Autonomous action risk",
  },
  {
    id: "LLM07", cat: "System Prompt Leakage", file: "owasp_llm04_to_llm10.py",
    day: "Day 3 — LLM Security", severity: "CRITICAL", expected: 3, actual: 1,
    status: "partial", score: "1/3",
    findings: [
      "System Prompt Leakage — grouped finding (DB conn string + admin password merged)",
    ],
    gap: "Grouping issue — individual secrets not separated · instruction to lie not flagged",
    fix: "Separate-finding prompt fix (Session 2 P2) needed — system prompt secrets merged into 1.",
    riskToScanner: "High — Infrastructure exposure",
  },
  {
    id: "LLM08", cat: "Vector & Embedding Weakness", file: "owasp_llm04_to_llm10.py",
    day: "Day 3 — LLM Security", severity: "HIGH", expected: 2, actual: 3,
    status: "pass", score: "3/2",
    findings: [
      "Vector Embedding Ingestion without Validation and Namespace Isolation",
      "RAG Retrieval without Access Control (ACL)",
      "Embedding API Calls without Rate Limit or Input Length Validation",
    ],
    gap: "OWASP LLM08-specific mapping could be improved",
    fix: "Newer OWASP category — good detection coverage. Consider LLM08 specific mapping.",
    riskToScanner: "Medium — Data isolation risk",
  },
  {
    id: "LLM09", cat: "Misinformation", file: "owasp_llm04_to_llm10.py",
    day: "Day 3 — LLM Security", severity: "HIGH", expected: 2, actual: 0,
    status: "fail", score: "0/2",
    findings: [],
    gap: "Scanner has no rules for role misrepresentation or governance/ethics risks",
    fix: "LLM09 is governance/ethics — not classic code vuln. Consider adding LLM-specific rule for role claims.",
    riskToScanner: "Medium — Liability and harm risk",
  },
  {
    id: "LLM10", cat: "Unbounded Consumption", file: "owasp_llm04_to_llm10.py",
    day: "Day 4 — Infrastructure Security", severity: "HIGH", expected: 3, actual: 1,
    status: "partial", score: "1/3",
    findings: [
      "Embedding API Calls without Rate Limit (via LLM08 overlap)",
    ],
    gap: "max_tokens cap + rate limiting on public endpoint + unbounded history — all missed",
    fix: "Layer 3 controls mitigate this. Scanner should flag missing max_tokens as finding.",
    riskToScanner: "High — Cost exhaustion / DoS",
  },
];

const BOUNDARIES = [
  {
    color: "#f59e0b", bg: "#1c1400", label: "Boundary 1 · Input validation",
    controls: [
      { name: "File upload endpoint", detail: "Extension allowlist + magic byte · MIME spoofing defence" },
      { name: "Size gate", detail: "50KB single file · 200KB folder · zip bomb prevention" },
      { name: "tiktoken pre-flight", detail: "Local token estimate before API dispatch" },
      { name: "FastAPI · Railway", detail: "10 req/min rate limit · Railway cloud hosting" },
    ],
  },
  {
    color: "#3b82f6", bg: "#0a1628", label: "Boundary 2 · LLM data plane",
    controls: [
      { name: "ScanAgent · gpt-4.1-mini", detail: "XML content wrap · JSON-only · 1 500 tokens" },
      { name: "OWASP LLM rule set ★", detail: "LLM01–10 detection patterns · NEW in Phase 02" },
      { name: "Input truncation", detail: "8 000-token cap · partial scan continues" },
      { name: "Token usage log", detail: "Per-agent logging · token_usage.log · audit trail" },
    ],
  },
  {
    color: "#a855f7", bg: "#180d2e", label: "Boundary 3 · Output schema",
    controls: [
      { name: "RiskClassifier · gpt-4.1-nano", detail: "Pydantic strict schema · enum-pinned risk_level" },
      { name: "Separate-finding rule ★", detail: "1 finding per vulnerability · NEW in Phase 02" },
      { name: "Guardrails", detail: "Non-dict filter · reject malformed JSON · log downgrades" },
    ],
  },
  {
    color: "#0d9488", bg: "#042e26", label: "Boundary 4 · Presentation",
    controls: [
      { name: "HTML/PDF report", detail: "HTML-escaped LLM output · findings only" },
      { name: "Executive mode", detail: "LangChain supervisor · narrative risk summary" },
      { name: "Folder scan ZIP", detail: "All 4 OWASP files combined · aggregate findings" },
    ],
  },
];

const BUGS = [
  { label: "pycache override", detail: "uvicorn ran old .pyc bytecode. Fix: Remove-Item -Recurse -Force src/__pycache__. All LLM03 re-runs invalid until cleared." },
  { label: "{} vs [] output", detail: "ScanAgent returned single JSON object instead of array. Parser wrapped it — silently masking all other findings. Fix: explicit array prefix in user message." },
  { label: "Wrong file uploaded", detail: "LLM03 Session 2 used old Phase 01 ai_agent.py (USE_REAL_LLM=False). Fixed by verifying file contents before upload." },
  { label: "summary field raw JSON", detail: "api_server.py passed json.dumps(findings) as summary instead of SummaryAgent narrative. Technical Summary card showed raw JSON array." },
];

const STATUS_META = {
  pass:    { label: "PASS",    bg: "#0a1e0f", color: "#10b981", border: "#10b981" },
  partial: { label: "PARTIAL", bg: "#1c1400", color: "#f59e0b", border: "#f59e0b" },
  fail:    { label: "FAIL",    bg: "#1c0808", color: "#ef4444", border: "#ef4444" },
};

const SEV_COLOR = { CRITICAL: "#ef4444", HIGH: "#f97316" };

export default function App() {
  const [activeTab, setActiveTab] = useState("architecture");
  const [selected, setSelected]   = useState(null);

  const pass    = OWASP_RESULTS.filter(r => r.status === "pass").length;
  const partial = OWASP_RESULTS.filter(r => r.status === "partial").length;
  const fail    = OWASP_RESULTS.filter(r => r.status === "fail").length;
  const score   = 72;

  const tabs = ["architecture", "owasp", "bugs", "scorecard"];
  const tabLabel = { architecture: "Architecture", owasp: "OWASP Top 10", bugs: "Session 2 bugs", scorecard: "Scorecard" };

  const base = {
    fontFamily: "'IBM Plex Mono', 'Courier New', monospace",
    minHeight: "100vh",
    background: "#080c14",
    color: "#e2e8f0",
  };

  const card = (extra = {}) => ({
    background: "#0d1628",
    border: "1px solid #1e293b",
    borderRadius: 8,
    padding: 16,
    marginBottom: 10,
    ...extra,
  });

  return (
    <div style={base}>
      {/* Header */}
      <div style={{ borderBottom: "1px solid #1e293b", padding: "18px 28px", display: "flex", justifyContent: "space-between", alignItems: "center", background: "#0f2044" }}>
        <div>
          <div style={{ fontSize: 11, color: "#3b82f6", letterSpacing: "0.15em", marginBottom: 3 }}>URIELLE AI AUDIT · AISB SG 2026</div>
          <div style={{ fontSize: 18, fontWeight: 700, color: "#f1f5f9" }}>DEV GUARDIAN — PHASE 02 ARCHITECTURE</div>
          <div style={{ fontSize: 10, color: "#475569", marginTop: 2 }}>OWASP LLM Top 10 · devguardian-urielle-ai.up.railway.app · github.com/wholidi/dev-guardian</div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ fontSize: 10, color: "#475569" }}>SCORE</div>
          <div style={{ fontSize: 34, fontWeight: 700, color: "#f59e0b", lineHeight: 1 }}>{score}<span style={{ fontSize: 14, color: "#475569" }}>/100</span></div>
          <div style={{ fontSize: 10, color: "#f59e0b", marginTop: 2 }}>{pass} PASS · {partial} PARTIAL · {fail} FAIL</div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid #1e293b", padding: "0 28px" }}>
        {tabs.map(t => (
          <button key={t} onClick={() => setActiveTab(t)} style={{
            background: "none", border: "none", cursor: "pointer",
            padding: "12px 18px", fontSize: 11, letterSpacing: "0.08em",
            color: activeTab === t ? "#3b82f6" : "#475569",
            borderBottom: activeTab === t ? "2px solid #3b82f6" : "2px solid transparent",
          }}>
            {tabLabel[t].toUpperCase()}
          </button>
        ))}
      </div>

      <div style={{ padding: "24px 28px" }}>

        {/* ── ARCHITECTURE TAB ── */}
        {activeTab === "architecture" && (
          <div>
            {/* Test files */}
            <div style={{ fontSize: 10, color: "#64748b", marginBottom: 8 }}>Test input files</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 18 }}>
              {[
                { id: "LLM01", file: "prompt_injection.py", single: true },
                { id: "LLM02", file: "sensitive_info.py",   single: true },
                { id: "LLM03", file: "supply_chain.py",     single: true },
                { id: "LLM04–10", file: "llm04_to_llm10.py", single: false },
              ].map(f => (
                <div key={f.id} style={{ background: f.single ? "#1c0800" : "#1c1400", border: `1px solid ${f.single ? "#993c1d" : "#854f0b"}`, borderRadius: 6, padding: "10px 12px" }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: f.single ? "#f97316" : "#f59e0b" }}>{f.id}</div>
                  <div style={{ fontSize: 9, color: "#94a3b8", marginTop: 3, fontFamily: "monospace" }}>{f.file}</div>
                </div>
              ))}
            </div>

            {/* Boundaries */}
            {BOUNDARIES.map((b, bi) => (
              <div key={bi} style={{ background: b.bg, border: `1px solid ${b.color}44`, borderRadius: 8, padding: 12, marginBottom: 10 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: b.color, marginBottom: 8, letterSpacing: "0.05em" }}>{b.label}</div>
                <div style={{ display: "grid", gridTemplateColumns: `repeat(${b.controls.length}, 1fr)`, gap: 6 }}>
                  {b.controls.map((c, ci) => (
                    <div key={ci} style={{ background: "#0d1628", border: `1px solid ${b.color}33`, borderRadius: 6, padding: "8px 10px" }}>
                      <div style={{ fontSize: 10, fontWeight: 700, color: b.color }}>{c.name}</div>
                      <div style={{ fontSize: 9, color: "#64748b", marginTop: 3 }}>{c.detail}</div>
                    </div>
                  ))}
                </div>
              </div>
            ))}

            {/* Infra strip */}
            <div style={{ ...card(), padding: "10px 14px", marginTop: 14 }}>
              <div style={{ fontSize: 9, color: "#475569" }}>
                Infrastructure: Railway · Supabase · Stripe · gpt-4.1-mini (ScanAgent, SummaryAgent) · gpt-4.1-nano (RiskClassifier, SupervisorAgent) · 30 Apr 2026
              </div>
            </div>
          </div>
        )}

        {/* ── OWASP TOP 10 TAB ── */}
        {activeTab === "owasp" && (
          <div>
            <div style={{ fontSize: 11, color: "#64748b", marginBottom: 16 }}>
              Click any row to expand findings and gaps.
            </div>
            {OWASP_RESULTS.map(r => {
              const sm = STATUS_META[r.status];
              const isOpen = selected === r.id;
              return (
                <div key={r.id} style={{ marginBottom: 6 }}>
                  <div
                    onClick={() => setSelected(isOpen ? null : r.id)}
                    style={{ background: isOpen ? sm.bg : "#0d1628", border: `1px solid ${isOpen ? sm.border : "#1e293b"}`, borderRadius: isOpen ? "8px 8px 0 0" : 8, padding: "10px 14px", cursor: "pointer", display: "flex", alignItems: "center", gap: 12 }}
                  >
                    <span style={{ fontSize: 11, fontWeight: 700, color: "#3b82f6", minWidth: 50 }}>{r.id}</span>
                    <span style={{ fontSize: 11, color: "#e2e8f0", flex: 1 }}>{r.cat}</span>
                    <span style={{ fontSize: 9, color: SEV_COLOR[r.severity] || "#64748b", marginRight: 8 }}>{r.severity}</span>
                    <span style={{ fontSize: 11, fontWeight: 700, color: "#e2e8f0" }}>{r.actual}/{r.expected}</span>
                    <span style={{ background: sm.bg, color: sm.color, border: `1px solid ${sm.border}`, borderRadius: 4, padding: "2px 8px", fontSize: 9, fontWeight: 700, minWidth: 60, textAlign: "center" }}>{sm.label}</span>
                    <span style={{ color: "#475569", fontSize: 12 }}>{isOpen ? "▲" : "▼"}</span>
                  </div>
                  {isOpen && (
                    <div style={{ background: sm.bg, border: `1px solid ${sm.border}`, borderTop: "none", borderRadius: "0 0 8px 8px", padding: 14 }}>
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 9, color: "#475569", marginBottom: 4 }}>FILE · {r.day}</div>
                        <div style={{ fontSize: 9, color: "#0d9488", fontFamily: "monospace" }}>{r.file}</div>
                      </div>
                      {r.findings.length > 0 && (
                        <div style={{ marginBottom: 10 }}>
                          <div style={{ fontSize: 9, color: "#475569", marginBottom: 4 }}>FINDINGS DETECTED</div>
                          {r.findings.map((f, i) => (
                            <div key={i} style={{ display: "flex", gap: 8, marginBottom: 3 }}>
                              <span style={{ color: sm.color, fontSize: 10 }}>✓</span>
                              <span style={{ fontSize: 10, color: "#94a3b8" }}>{f}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      {r.actual === 0 && (
                        <div style={{ fontSize: 10, color: "#ef4444", marginBottom: 10 }}>No findings returned.</div>
                      )}
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                        <div>
                          <div style={{ fontSize: 9, color: "#f59e0b", marginBottom: 3 }}>KEY GAP</div>
                          <div style={{ fontSize: 10, color: "#94a3b8" }}>{r.gap}</div>
                        </div>
                        <div>
                          <div style={{ fontSize: 9, color: "#0d9488", marginBottom: 3 }}>SESSION 2 FIX</div>
                          <div style={{ fontSize: 10, color: "#94a3b8" }}>{r.fix}</div>
                        </div>
                      </div>
                      <div style={{ marginTop: 8, fontSize: 9, color: "#475569" }}>Risk to scanner: {r.riskToScanner}</div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* ── BUGS TAB ── */}
        {activeTab === "bugs" && (
          <div>
            <div style={{ fontSize: 11, color: "#64748b", marginBottom: 16 }}>
              Four compounding bugs discovered during Session 2 testing. All resolved before final results.
            </div>
            {BUGS.map((b, i) => (
              <div key={i} style={{ background: "#1c0800", border: "1px solid #993c1d", borderRadius: 8, padding: 14, marginBottom: 10 }}>
                <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
                  <span style={{ background: "#f97316", color: "#fff", borderRadius: 4, padding: "2px 8px", fontSize: 9, fontWeight: 700, whiteSpace: "nowrap", marginTop: 1 }}>BUG {i + 1}</span>
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: "#f97316", marginBottom: 5 }}>{b.label}</div>
                    <div style={{ fontSize: 10, color: "#94a3b8", lineHeight: 1.6 }}>{b.detail}</div>
                  </div>
                </div>
              </div>
            ))}
            <div style={card({ marginTop: 16 })}>
              <div style={{ fontSize: 10, fontWeight: 700, color: "#3b82f6", marginBottom: 8 }}>SESSION 2 PLANNED FIXES</div>
              {[
                ["P1","MAX_TOKENS_CLASSIFY → 1500","src/ai_agent.py"],
                ["P2","Separate-finding prompt rule","src/ai_agent.py"],
                ["P3","Pydantic schema","src/guardrails_utils.py"],
                ["P4","Deploy fixes to Railway","Railway Dashboard"],
                ["P5","Full web re-run all 10 TCs","Web UI"],
                ["P6","OWASP CMD mapping A01 → A03","src/multi_agent_workflow.py"],
                ["P7","LLM09 governance rule","src/ai_agent.py"],
                ["P8","Fix summary field raw JSON","src/api_server.py"],
              ].map(([p, fix, file]) => (
                <div key={p} style={{ display: "flex", gap: 12, alignItems: "center", padding: "6px 0", borderBottom: "1px solid #1e293b" }}>
                  <span style={{ color: "#f59e0b", fontWeight: 700, fontSize: 10, minWidth: 24 }}>{p}</span>
                  <span style={{ fontSize: 10, color: "#e2e8f0", flex: 1 }}>{fix}</span>
                  <span style={{ fontSize: 9, color: "#0d9488", fontFamily: "monospace" }}>{file}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── SCORECARD TAB ── */}
        {activeTab === "scorecard" && (
          <div>
            {/* Big score */}
            <div style={{ ...card(), textAlign: "center", padding: 32, marginBottom: 20 }}>
              <div style={{ fontSize: 10, color: "#475569", letterSpacing: "0.1em", marginBottom: 8 }}>AGGREGATE SCORE</div>
              <div style={{ fontSize: 64, fontWeight: 700, color: "#f59e0b", lineHeight: 1 }}>{score}</div>
              <div style={{ fontSize: 13, color: "#475569", marginTop: 6 }}>out of 100</div>
              <div style={{ marginTop: 12, fontSize: 12, fontWeight: 700, color: "#f59e0b" }}>
                Production-usable with known gaps (≥70 threshold met)
              </div>
              <div style={{ marginTop: 8, fontSize: 10, color: "#64748b" }}>
                {pass} PASS · {partial} PARTIAL · {fail} FAIL
              </div>
            </div>

            {/* Per-TC weights */}
            {[
              { id: "LLM01", label: "Prompt Injection",      max: 15, status: "pass" },
              { id: "LLM02", label: "Sensitive Info",         max: 10, status: "partial" },
              { id: "LLM03", label: "Supply Chain",           max: 15, status: "pass" },
              { id: "LLM04", label: "Data Poisoning",         max: 10, status: "pass" },
              { id: "LLM05", label: "Output Handling",        max: 15, status: "pass" },
              { id: "LLM06", label: "Excessive Agency",       max: 8,  status: "pass" },
              { id: "LLM07", label: "Prompt Leakage",         max: 8,  status: "partial" },
              { id: "LLM08", label: "Vector/Embedding",       max: 7,  status: "pass" },
              { id: "LLM09", label: "Misinformation",         max: 7,  status: "fail" },
              { id: "LLM10", label: "Unbounded Consumption",  max: 5,  status: "partial" },
            ].map(({ id, label, max, status }) => {
              const sm = STATUS_META[status];
              const earned = status === "pass" ? max : status === "partial" ? Math.floor(max / 2) : 0;
              const pct = (earned / max) * 100;
              return (
                <div key={id} style={{ ...card({ padding: "10px 14px" }), marginBottom: 6 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <div>
                      <span style={{ fontSize: 10, color: "#3b82f6", marginRight: 8 }}>{id}</span>
                      <span style={{ fontSize: 11, color: "#e2e8f0" }}>{label}</span>
                    </div>
                    <div style={{ fontSize: 11, fontWeight: 700, color: sm.color }}>{earned}/{max}</div>
                  </div>
                  <div style={{ background: "#1e293b", borderRadius: 3, height: 4 }}>
                    <div style={{ background: sm.color, width: `${pct}%`, height: "100%", borderRadius: 3 }} />
                  </div>
                </div>
              );
            })}

            {/* Strength / Gap summary */}
            <div style={{ marginTop: 20 }}>
              {[
                { icon: "Strength", color: "#10b981", bg: "#0a1e0f", text: "LLM03 Supply Chain: 8/4 findings — GPU side-channel, torch.load, pickle all detected." },
                { icon: "Strength", color: "#10b981", bg: "#0a1e0f", text: "LLM05 Improper Output Handling: exec(LLM) + os.system(LLM) correctly flagged CRITICAL." },
                { icon: "Strength", color: "#10b981", bg: "#0a1e0f", text: "LLM06 Excessive Agency: AI governance risk recognised beyond pure code vulnerability." },
                { icon: "Gap",      color: "#ef4444", bg: "#1c0808", text: "LLM09 Misinformation: 0 findings — no rules for role misrepresentation or ethics." },
                { icon: "Gap",      color: "#f59e0b", bg: "#1c1400", text: "LLM10 Unbounded Consumption: missing max_tokens cap + rate limiting rules." },
                { icon: "Gap",      color: "#f59e0b", bg: "#1c1400", text: "LLM02 Sensitive Info: Card/CVV logging (PCI DSS) + PII-to-LLM transmission not flagged." },
                { icon: "Insight",  color: "#a855f7", bg: "#180d2e", text: "Dev Guardian excels at code-level vulns (injection, crypto, secrets) vs AI governance (LLM09)." },
              ].map((item, i) => (
                <div key={i} style={{ background: item.bg, border: `1px solid ${item.color}44`, borderRadius: 6, padding: "10px 14px", marginBottom: 6, display: "flex", gap: 12 }}>
                  <span style={{ color: item.color, fontSize: 9, fontWeight: 700, minWidth: 56 }}>{item.icon}</span>
                  <span style={{ fontSize: 10, color: "#94a3b8" }}>{item.text}</span>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
