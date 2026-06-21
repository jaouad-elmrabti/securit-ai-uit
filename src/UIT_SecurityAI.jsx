import { useState, useRef, useEffect } from "react";

// ─── Palette & Design ───────────────────────────────────────────────────────
// Deep navy + electric cyan on dark  (cybersecurity terminal aesthetic)
// Monospace terminal for outputs, clean sans for UI

const COLORS = {
  bg: "#0a0e1a",
  surface: "#111827",
  panel: "#1a2235",
  border: "#1e3a5f",
  cyan: "#00d4ff",
  green: "#00ff88",
  red: "#ff4444",
  orange: "#ff9500",
  yellow: "#ffd600",
  purple: "#a855f7",
  text: "#e2e8f0",
  muted: "#64748b",
  dim: "#334155",
};

// ─── OWASP Top 10 Dataset (basé sur le rapport UIT) ─────────────────────────
const OWASP_CHECKS = [
  {
    id: "A01",
    name: "Contrôle d'accès défaillant",
    severity: "CRITIQUE",
    payloads: ["../../../etc/passwd", "?id=1&role=admin", "/admin", "/dashboard?user=2"],
    description: "Vérifie si des ressources protégées sont accessibles sans autorisation.",
    fix: "Implémenter RBAC strict. Valider les autorisations côté serveur à chaque requête.",
  },
  {
    id: "A02",
    name: "Défaillances cryptographiques",
    severity: "CRITIQUE",
    payloads: ["Vérification TLS/HTTPS", "Analyse des headers SSL", "Détection HTTP non chiffré"],
    description: "Vérifie la présence de TLS 1.3, HSTS et le chiffrement des données sensibles.",
    fix: "Déployer TLS 1.3 + HSTS avec includeSubDomains. Désactiver TLS 1.0/1.1.",
  },
  {
    id: "A03",
    name: "Injection SQL / XSS / NoSQL",
    severity: "ÉLEVÉ",
    payloads: ["' OR '1'='1", "<script>alert(1)</script>", "admin'--", "1; DROP TABLE users--"],
    description: "Teste les points d'injection dans les formulaires et paramètres URL.",
    fix: "Utiliser des requêtes préparées (PDO/PreparedStatement). Échapper les sorties HTML.",
  },
  {
    id: "A04",
    name: "Conception non sécurisée",
    severity: "ÉLEVÉ",
    payloads: ["Analyse architecture", "Vérification séparation des rôles", "Test logique métier"],
    description: "Évalue la robustesse de la conception de sécurité de l'application.",
    fix: "Threat modeling dès la phase de conception. Revue de code sécurité obligatoire.",
  },
  {
    id: "A05",
    name: "Mauvaise configuration sécurité",
    severity: "ÉLEVÉ",
    payloads: ["X-Frame-Options", "Content-Security-Policy", "X-XSS-Protection", "Server: Apache"],
    description: "Vérifie les headers HTTP, bannières de version et configurations par défaut.",
    fix: "Configurer tous les headers sécurité. Masquer les bannières de version serveur.",
  },
  {
    id: "A07",
    name: "Défaillances d'authentification",
    severity: "ÉLEVÉ",
    payloads: ["Test brute force", "admin/admin", "Test MFA absente", "Session sans expiration"],
    description: "Teste la robustesse de l'authentification et la gestion des sessions.",
    fix: "Implémenter MFA obligatoire pour admins. Verrouillage après 5 tentatives échouées.",
  },
  {
    id: "A09",
    name: "Journalisation insuffisante",
    severity: "MOYEN",
    payloads: ["Test logs d'accès", "Vérification alertes sécurité", "Test SIEM"],
    description: "Vérifie si les événements de sécurité sont correctement enregistrés.",
    fix: "Déployer un SIEM centralisé. Logger toutes les tentatives d'authentification.",
  },
  {
    id: "A10",
    name: "SSRF — Server-Side Request Forgery",
    severity: "MOYEN",
    payloads: ["http://localhost:8080", "http://169.254.169.254/latest/meta-data/", "http://internal-api/"],
    description: "Teste si le serveur peut être forcé à effectuer des requêtes internes.",
    fix: "Valider et filtrer toutes les URL fournies par l'utilisateur. Utiliser une allowlist.",
  },
];

// ─── UIT Target Sites ────────────────────────────────────────────────────────
const UIT_TARGETS = [
  { name: "Portail Principal UIT", url: "https://www.uit.ac.ma", type: "Site institutionnel" },
  { name: "Portail Étudiant", url: "https://portail.uit.ac.ma", type: "Application académique" },
  { name: "Plateforme E-Learning", url: "https://elearning.uit.ac.ma", type: "Plateforme pédagogique" },
  { name: "Messagerie Institutionnelle", url: "https://mail.uit.ac.ma", type: "Service email" },
  { name: "Système de Gestion RH", url: "https://rh.uit.ac.ma", type: "Application RH" },
];

// ─── AI Security Analysis Engine ─────────────────────────────────────────────
async function runAISecurityAnalysis(target, checks, onProgress) {
  const systemPrompt = `Tu es SECURIT-AI, un expert en cybersécurité spécialisé dans l'audit des systèmes universitaires.
Tu analyses les applications web de l'Université Ibn Tofail selon le framework OWASP Top 10 2021.
CONTEXTE: Rapport de sécurité UIT 2025-2026 (Pr. Younes Chihab)
RÈGLES STRICTES:
- Tu effectues UNIQUEMENT une analyse théorique et éducative
- Tu ne génères PAS de code malveillant réel
- Tes résultats sont des SIMULATIONS pédagogiques basées sur le rapport fourni
- Format de réponse: JSON uniquement

Réponds UNIQUEMENT avec du JSON valide, sans texte avant ou après.`;

  const checksDesc = checks.map(c => `${c.id}: ${c.name} (${c.severity})`).join("\n");

  const userPrompt = `Analyse de sécurité SIMULÉE pour: ${target.name} (${target.url})
Type: ${target.type}

Vulnérabilités OWASP à vérifier:
${checksDesc}

Génère un rapport JSON avec cette structure EXACTE:
{
  "target": "${target.name}",
  "url": "${target.url}",
  "score": <number 0-100>,
  "risk_level": "<CRITIQUE|ÉLEVÉ|MOYEN|FAIBLE>",
  "summary": "<résumé 2 phrases>",
  "findings": [
    {
      "check_id": "<A01|A02|...>",
      "check_name": "<nom>",
      "status": "<VULNÉRABLE|ATTENTION|CONFORME>",
      "severity": "<CRITIQUE|ÉLEVÉ|MOYEN|FAIBLE>",
      "detail": "<explication spécifique au contexte universitaire>",
      "evidence": "<exemple de payload ou indicateur trouvé>",
      "recommendation": "<action corrective précise>"
    }
  ],
  "priority_actions": ["<action1>", "<action2>", "<action3>"],
  "compliance": {
    "owasp_score": <number 0-10>,
    "rgpd_risk": "<HAUT|MOYEN|FAIBLE>",
    "loi_09_08_risk": "<HAUT|MOYEN|FAIBLE>"
  }
}`;

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-6",
      max_tokens: 1000,
      system: systemPrompt,
      messages: [{ role: "user", content: userPrompt }],
    }),
  });

  if (!response.ok) throw new Error(`API Error: ${response.status}`);
  const data = await response.json();
  const text = data.content.map(i => i.text || "").join("");
  const clean = text.replace(/```json|```/g, "").trim();
  return JSON.parse(clean);
}

// ─── Training Dataset Generator ───────────────────────────────────────────────
async function generateTrainingData(scenario) {
  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "claude-sonnet-4-6",
      max_tokens: 1000,
      messages: [{
        role: "user",
        content: `Génère 3 exemples d'entraînement pour un modèle IA de détection de ${scenario} dans un contexte universitaire (UIT).
Chaque exemple doit avoir: input (requête HTTP simulée), label (VULNÉRABLE/SAIN), explanation.
Format JSON UNIQUEMENT:
{"examples": [{"input": "...", "label": "...", "explanation": "..."}]}`
      }],
    }),
  });
  const data = await response.json();
  const text = data.content.map(i => i.text || "").join("");
  const clean = text.replace(/```json|```/g, "").trim();
  return JSON.parse(clean);
}

// ─── Severity Color ───────────────────────────────────────────────────────────
function severityColor(s) {
  if (!s) return COLORS.muted;
  const u = s.toUpperCase();
  if (u === "CRITIQUE") return COLORS.red;
  if (u === "ÉLEVÉ" || u === "ELEVE") return COLORS.orange;
  if (u === "MOYEN") return COLORS.yellow;
  return COLORS.green;
}

function statusColor(s) {
  if (!s) return COLORS.muted;
  const u = s.toUpperCase();
  if (u === "VULNÉRABLE" || u === "VULNERABLE") return COLORS.red;
  if (u === "ATTENTION") return COLORS.orange;
  return COLORS.green;
}

// ─── Component: Animated Score Ring ──────────────────────────────────────────
function ScoreRing({ score }) {
  const r = 42, circ = 2 * Math.PI * r;
  const dash = circ * (1 - score / 100);
  const col = score < 40 ? COLORS.red : score < 70 ? COLORS.orange : COLORS.green;
  return (
    <svg viewBox="0 0 100 100" width="100" height="100" style={{ display: "block" }}>
      <circle cx="50" cy="50" r={r} fill="none" stroke={COLORS.dim} strokeWidth="8" />
      <circle
        cx="50" cy="50" r={r} fill="none" stroke={col} strokeWidth="8"
        strokeDasharray={circ} strokeDashoffset={dash}
        strokeLinecap="round" transform="rotate(-90 50 50)"
        style={{ transition: "stroke-dashoffset 1s ease" }}
      />
      <text x="50" y="46" textAnchor="middle" fill={col} fontSize="20" fontWeight="bold" fontFamily="monospace">{score}</text>
      <text x="50" y="60" textAnchor="middle" fill={COLORS.muted} fontSize="9" fontFamily="monospace">/100</text>
    </svg>
  );
}

// ─── Component: Terminal Log ──────────────────────────────────────────────────
function TerminalLog({ logs }) {
  const ref = useRef(null);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [logs]);
  return (
    <div ref={ref} style={{
      background: "#050810", border: `1px solid ${COLORS.border}`,
      borderRadius: 8, padding: "12px 16px", fontFamily: "monospace",
      fontSize: 12, color: COLORS.green, height: 160, overflowY: "auto",
      lineHeight: 1.6
    }}>
      {logs.map((l, i) => (
        <div key={i} style={{ color: l.type === "error" ? COLORS.red : l.type === "warn" ? COLORS.orange : l.type === "info" ? COLORS.cyan : COLORS.green }}>
          <span style={{ color: COLORS.muted }}>[{l.time}] </span>{l.msg}
        </div>
      ))}
      {logs.length === 0 && <span style={{ color: COLORS.muted }}>En attente de scan...</span>}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function UIT_SecurityAI() {
  const [activeTab, setActiveTab] = useState("scanner");
  const [selectedTarget, setSelectedTarget] = useState(UIT_TARGETS[0]);
  const [selectedChecks, setSelectedChecks] = useState(OWASP_CHECKS.map(c => c.id));
  const [scanning, setScanning] = useState(false);
  const [report, setReport] = useState(null);
  const [logs, setLogs] = useState([]);
  const [trainingScenario, setTrainingScenario] = useState("Injection SQL");
  const [trainingData, setTrainingData] = useState(null);
  const [trainingLoading, setTrainingLoading] = useState(false);
  const [history, setHistory] = useState([]);

  const addLog = (msg, type = "ok") => {
    const time = new Date().toLocaleTimeString("fr-FR");
    setLogs(prev => [...prev.slice(-50), { msg, type, time }]);
  };

  const runScan = async () => {
    if (scanning) return;
    setScanning(true);
    setReport(null);
    setLogs([]);
    addLog(`🔍 Initialisation du scan SECURIT-AI v2.0`, "info");
    addLog(`🎯 Cible: ${selectedTarget.name} (${selectedTarget.url})`, "info");
    addLog(`📋 ${selectedChecks.length} vérifications OWASP sélectionnées`, "info");

    const checks = OWASP_CHECKS.filter(c => selectedChecks.includes(c.id));

    for (const check of checks) {
      await new Promise(r => setTimeout(r, 300));
      addLog(`⚡ Test ${check.id}: ${check.name}`, "ok");
      for (const p of check.payloads.slice(0, 2)) {
        await new Promise(r => setTimeout(r, 150));
        addLog(`   → Payload: ${p}`, "warn");
      }
    }

    addLog(`🤖 Analyse IA en cours...`, "info");

    try {
      const result = await runAISecurityAnalysis(selectedTarget, checks, addLog);
      setReport(result);
      setHistory(prev => [{ target: selectedTarget.name, score: result.score, risk: result.risk_level, date: new Date().toLocaleString("fr-FR") }, ...prev.slice(0, 4)]);
      addLog(`✅ Rapport généré — Score: ${result.score}/100 (${result.risk_level})`, result.score < 50 ? "error" : result.score < 75 ? "warn" : "ok");
    } catch (e) {
      addLog(`❌ Erreur: ${e.message}`, "error");
    }
    setScanning(false);
  };

  const runTraining = async () => {
    setTrainingLoading(true);
    setTrainingData(null);
    try {
      const data = await generateTrainingData(trainingScenario);
      setTrainingData(data);
    } catch (e) {
      alert("Erreur génération données d'entraînement: " + e.message);
    }
    setTrainingLoading(false);
  };

  // ── Styles ─────────────────────────────────────────────────────────────────
  const cardStyle = {
    background: COLORS.panel, border: `1px solid ${COLORS.border}`,
    borderRadius: 10, padding: 20, marginBottom: 16
  };
  const tabBtn = (id) => ({
    padding: "10px 20px", borderRadius: 6, cursor: "pointer", fontWeight: 600,
    fontSize: 13, border: "none", fontFamily: "monospace",
    background: activeTab === id ? COLORS.cyan : COLORS.dim,
    color: activeTab === id ? COLORS.bg : COLORS.text,
    transition: "all 0.2s"
  });
  const badge = (text, color) => (
    <span style={{
      background: color + "22", color, border: `1px solid ${color}`,
      borderRadius: 4, padding: "2px 8px", fontSize: 11, fontWeight: 700,
      fontFamily: "monospace", whiteSpace: "nowrap"
    }}>{text}</span>
  );

  return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", color: COLORS.text, fontFamily: "'Inter', sans-serif", padding: 20 }}>

      {/* Header */}
      <div style={{ textAlign: "center", marginBottom: 28, padding: "20px 0" }}>
        <div style={{ fontSize: 32, fontWeight: 900, letterSpacing: -1, fontFamily: "monospace" }}>
          <span style={{ color: COLORS.cyan }}>SECURIT</span>
          <span style={{ color: COLORS.purple }}>-AI</span>
          <span style={{ color: COLORS.muted, fontSize: 14, fontWeight: 400, marginLeft: 12 }}>v2.0</span>
        </div>
        <div style={{ color: COLORS.muted, fontSize: 13, marginTop: 6 }}>
          Système IA d'Audit de Sécurité · Université Ibn Tofail · OWASP Top 10 2021
        </div>
        <div style={{ display: "flex", justifyContent: "center", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
          {badge("OWASP Top 10", COLORS.cyan)}
          {badge("RGPD / Loi 09-08", COLORS.purple)}
          {badge("Analyse IA", COLORS.green)}
          {badge("Mode Éducatif", COLORS.orange)}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
        {[["scanner", "🔍 Scanner"], ["training", "🎓 Entraînement IA"], ["history", "📊 Historique"], ["guide", "📖 Guide"]].map(([id, label]) => (
          <button key={id} style={tabBtn(id)} onClick={() => setActiveTab(id)}>{label}</button>
        ))}
      </div>

      {/* ── TAB: SCANNER ─────────────────────────────────────────────────── */}
      {activeTab === "scanner" && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>

            {/* Target Selection */}
            <div style={cardStyle}>
              <div style={{ color: COLORS.cyan, fontWeight: 700, marginBottom: 12, fontSize: 13, fontFamily: "monospace" }}>
                🎯 CIBLE D'ANALYSE
              </div>
              {UIT_TARGETS.map(t => (
                <div key={t.url} onClick={() => setSelectedTarget(t)}
                  style={{
                    padding: "10px 12px", borderRadius: 6, marginBottom: 6, cursor: "pointer",
                    background: selectedTarget.url === t.url ? COLORS.cyan + "15" : COLORS.surface,
                    border: `1px solid ${selectedTarget.url === t.url ? COLORS.cyan : COLORS.dim}`,
                    transition: "all 0.15s"
                  }}>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{t.name}</div>
                  <div style={{ color: COLORS.muted, fontSize: 11, marginTop: 2 }}>{t.url}</div>
                  <div style={{ marginTop: 4 }}>{badge(t.type, COLORS.purple)}</div>
                </div>
              ))}
            </div>

            {/* Check Selection */}
            <div style={cardStyle}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                <div style={{ color: COLORS.cyan, fontWeight: 700, fontSize: 13, fontFamily: "monospace" }}>
                  ⚡ VÉRIFICATIONS OWASP
                </div>
                <button onClick={() => setSelectedChecks(selectedChecks.length === OWASP_CHECKS.length ? [] : OWASP_CHECKS.map(c => c.id))}
                  style={{ fontSize: 11, color: COLORS.cyan, background: "none", border: "none", cursor: "pointer" }}>
                  {selectedChecks.length === OWASP_CHECKS.length ? "Désélectionner tout" : "Sélectionner tout"}
                </button>
              </div>
              {OWASP_CHECKS.map(c => (
                <div key={c.id} onClick={() => setSelectedChecks(prev => prev.includes(c.id) ? prev.filter(x => x !== c.id) : [...prev, c.id])}
                  style={{
                    display: "flex", alignItems: "center", gap: 8, padding: "7px 10px",
                    borderRadius: 6, marginBottom: 4, cursor: "pointer",
                    background: selectedChecks.includes(c.id) ? COLORS.surface : "transparent",
                    border: `1px solid ${selectedChecks.includes(c.id) ? COLORS.dim : "transparent"}`
                  }}>
                  <div style={{
                    width: 14, height: 14, borderRadius: 3, border: `2px solid ${severityColor(c.severity)}`,
                    background: selectedChecks.includes(c.id) ? severityColor(c.severity) : "transparent",
                    flexShrink: 0
                  }} />
                  <span style={{ fontFamily: "monospace", fontSize: 11, color: COLORS.muted, width: 32 }}>{c.id}</span>
                  <span style={{ fontSize: 12, flex: 1 }}>{c.name}</span>
                  {badge(c.severity, severityColor(c.severity))}
                </div>
              ))}
            </div>
          </div>

          {/* Launch Button */}
          <div style={{ textAlign: "center", marginBottom: 16 }}>
            <button onClick={runScan} disabled={scanning || selectedChecks.length === 0}
              style={{
                padding: "14px 40px", borderRadius: 8, fontSize: 15, fontWeight: 700,
                fontFamily: "monospace", border: "none", cursor: scanning ? "not-allowed" : "pointer",
                background: scanning ? COLORS.dim : `linear-gradient(135deg, ${COLORS.cyan}, ${COLORS.purple})`,
                color: scanning ? COLORS.muted : COLORS.bg, letterSpacing: 1, transition: "all 0.2s",
                boxShadow: scanning ? "none" : `0 0 20px ${COLORS.cyan}44`
              }}>
              {scanning ? "⏳ ANALYSE EN COURS..." : `🚀 LANCER LE SCAN (${selectedChecks.length} tests)`}
            </button>
          </div>

          {/* Terminal */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ color: COLORS.muted, fontSize: 11, fontFamily: "monospace", marginBottom: 6 }}>TERMINAL DE SCAN</div>
            <TerminalLog logs={logs} />
          </div>

          {/* Report */}
          {report && (
            <div>
              {/* Score Header */}
              <div style={{ ...cardStyle, display: "flex", alignItems: "center", gap: 24, flexWrap: "wrap" }}>
                <ScoreRing score={report.score} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 18, fontWeight: 700 }}>{report.target}</div>
                  <div style={{ color: COLORS.muted, fontSize: 12, marginBottom: 8 }}>{report.url}</div>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
                    {badge(`Risque: ${report.risk_level}`, severityColor(report.risk_level))}
                    {badge(`OWASP: ${report.compliance?.owasp_score}/10`, COLORS.cyan)}
                    {badge(`RGPD: ${report.compliance?.rgpd_risk}`, severityColor(report.compliance?.rgpd_risk))}
                    {badge(`Loi 09-08: ${report.compliance?.loi_09_08_risk}`, severityColor(report.compliance?.loi_09_08_risk))}
                  </div>
                  <div style={{ color: COLORS.text, fontSize: 13, lineHeight: 1.5 }}>{report.summary}</div>
                </div>
              </div>

              {/* Findings */}
              <div style={cardStyle}>
                <div style={{ color: COLORS.cyan, fontWeight: 700, marginBottom: 14, fontSize: 13, fontFamily: "monospace" }}>
                  🔎 RÉSULTATS DÉTAILLÉS ({report.findings?.length} vérifications)
                </div>
                {(report.findings || []).map((f, i) => (
                  <div key={i} style={{
                    border: `1px solid ${statusColor(f.status)}33`,
                    borderLeft: `3px solid ${statusColor(f.status)}`,
                    borderRadius: 6, padding: 14, marginBottom: 10,
                    background: statusColor(f.status) + "08"
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 6, marginBottom: 6 }}>
                      <div style={{ fontWeight: 700, fontSize: 13 }}>
                        <span style={{ color: COLORS.muted, fontFamily: "monospace", marginRight: 8 }}>{f.check_id}</span>
                        {f.check_name}
                      </div>
                      <div style={{ display: "flex", gap: 6 }}>
                        {badge(f.status, statusColor(f.status))}
                        {badge(f.severity, severityColor(f.severity))}
                      </div>
                    </div>
                    <div style={{ fontSize: 12, color: COLORS.text, marginBottom: 6 }}>{f.detail}</div>
                    <div style={{ fontSize: 11, fontFamily: "monospace", color: COLORS.orange, background: COLORS.surface, padding: "4px 8px", borderRadius: 4, marginBottom: 6 }}>
                      Évidence: {f.evidence}
                    </div>
                    <div style={{ fontSize: 11, color: COLORS.green }}>✅ {f.recommendation}</div>
                  </div>
                ))}
              </div>

              {/* Priority Actions */}
              <div style={cardStyle}>
                <div style={{ color: COLORS.red, fontWeight: 700, marginBottom: 12, fontSize: 13, fontFamily: "monospace" }}>
                  🚨 ACTIONS PRIORITAIRES
                </div>
                {(report.priority_actions || []).map((a, i) => (
                  <div key={i} style={{ display: "flex", gap: 10, marginBottom: 8, alignItems: "flex-start" }}>
                    <div style={{ color: COLORS.red, fontWeight: 700, fontFamily: "monospace", minWidth: 20 }}>{i + 1}.</div>
                    <div style={{ fontSize: 13 }}>{a}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── TAB: TRAINING ────────────────────────────────────────────────── */}
      {activeTab === "training" && (
        <div>
          <div style={cardStyle}>
            <div style={{ color: COLORS.cyan, fontWeight: 700, marginBottom: 4, fontSize: 13, fontFamily: "monospace" }}>
              🎓 GÉNÉRATEUR DE DONNÉES D'ENTRAÎNEMENT IA
            </div>
            <div style={{ color: COLORS.muted, fontSize: 12, marginBottom: 16 }}>
              Génère des exemples étiquetés pour entraîner un modèle de détection de menaces spécifique à l'UIT.
            </div>

            <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
              <select value={trainingScenario} onChange={e => setTrainingScenario(e.target.value)}
                style={{
                  flex: 1, minWidth: 200, background: COLORS.surface, border: `1px solid ${COLORS.border}`,
                  color: COLORS.text, padding: "10px 14px", borderRadius: 6, fontSize: 13
                }}>
                {["Injection SQL", "Cross-Site Scripting (XSS)", "Brute Force d'authentification",
                  "CSRF", "SSRF", "Traversal de répertoire", "Contrôle d'accès défaillant"].map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
              <button onClick={runTraining} disabled={trainingLoading}
                style={{
                  padding: "10px 24px", borderRadius: 6, fontWeight: 700, fontFamily: "monospace",
                  background: trainingLoading ? COLORS.dim : COLORS.purple, color: COLORS.bg,
                  border: "none", cursor: trainingLoading ? "not-allowed" : "pointer", fontSize: 13
                }}>
                {trainingLoading ? "⏳ Génération..." : "⚡ Générer exemples"}
              </button>
            </div>

            {trainingData && (
              <div>
                <div style={{ color: COLORS.green, fontWeight: 600, marginBottom: 12, fontSize: 13 }}>
                  ✅ {trainingData.examples?.length} exemples générés pour: {trainingScenario}
                </div>
                {(trainingData.examples || []).map((ex, i) => (
                  <div key={i} style={{
                    border: `1px solid ${ex.label === "VULNÉRABLE" ? COLORS.red : COLORS.green}33`,
                    borderRadius: 8, padding: 14, marginBottom: 10
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                      <span style={{ color: COLORS.muted, fontSize: 11, fontFamily: "monospace" }}>EXEMPLE #{i + 1}</span>
                      {badge(ex.label, ex.label === "VULNÉRABLE" ? COLORS.red : COLORS.green)}
                    </div>
                    <div style={{ fontFamily: "monospace", fontSize: 11, background: COLORS.surface, padding: 10, borderRadius: 4, marginBottom: 8, color: COLORS.orange, wordBreak: "break-all" }}>
                      {ex.input}
                    </div>
                    <div style={{ fontSize: 12, color: COLORS.text }}>{ex.explanation}</div>
                  </div>
                ))}

                <div style={{ marginTop: 16, padding: 14, background: COLORS.surface, borderRadius: 8, border: `1px solid ${COLORS.border}` }}>
                  <div style={{ color: COLORS.cyan, fontWeight: 700, marginBottom: 8, fontSize: 12, fontFamily: "monospace" }}>
                    📤 EXPORT JSON (Données d'entraînement)
                  </div>
                  <pre style={{ fontFamily: "monospace", fontSize: 10, color: COLORS.green, overflowX: "auto", maxHeight: 150, background: "#050810", padding: 10, borderRadius: 4 }}>
                    {JSON.stringify(trainingData, null, 2)}
                  </pre>
                </div>
              </div>
            )}
          </div>

          {/* Training Pipeline */}
          <div style={cardStyle}>
            <div style={{ color: COLORS.cyan, fontWeight: 700, marginBottom: 14, fontSize: 13, fontFamily: "monospace" }}>
              🔄 PIPELINE D'ENTRAÎNEMENT IA — ARCHITECTURE
            </div>
            {[
              { step: "1", title: "Collecte de données", desc: "Logs Apache/Nginx de l'UIT, requêtes HTTP normales vs malveillantes, payloads OWASP.", color: COLORS.cyan },
              { step: "2", title: "Étiquetage (Labeling)", desc: "Classification: VULNÉRABLE / SUSPECT / SAIN via l'IA et validation manuelle par l'équipe DSI.", color: COLORS.purple },
              { step: "3", title: "Feature Engineering", desc: "Extraction: longueur URL, caractères spéciaux, patterns SQL/XSS, headers HTTP, user-agents.", color: COLORS.orange },
              { step: "4", title: "Entraînement du modèle", desc: "Algorithmes: Random Forest + LSTM pour détection séquentielle. Validation croisée 80/20.", color: COLORS.yellow },
              { step: "5", title: "Déploiement WAF IA", desc: "Intégration avec ModSecurity. Alertes temps réel vers SIEM. Feedback loop continu.", color: COLORS.green },
            ].map(s => (
              <div key={s.step} style={{ display: "flex", gap: 12, marginBottom: 10, alignItems: "flex-start" }}>
                <div style={{
                  width: 28, height: 28, borderRadius: "50%", background: s.color + "22",
                  border: `2px solid ${s.color}`, display: "flex", alignItems: "center", justifyContent: "center",
                  fontWeight: 700, fontFamily: "monospace", fontSize: 12, color: s.color, flexShrink: 0
                }}>{s.step}</div>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 2 }}>{s.title}</div>
                  <div style={{ fontSize: 12, color: COLORS.muted }}>{s.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── TAB: HISTORY ─────────────────────────────────────────────────── */}
      {activeTab === "history" && (
        <div style={cardStyle}>
          <div style={{ color: COLORS.cyan, fontWeight: 700, marginBottom: 14, fontSize: 13, fontFamily: "monospace" }}>
            📊 HISTORIQUE DES SCANS
          </div>
          {history.length === 0 ? (
            <div style={{ color: COLORS.muted, textAlign: "center", padding: 40, fontSize: 13 }}>
              Aucun scan effectué. Lancez votre premier audit depuis l'onglet Scanner.
            </div>
          ) : (
            <div>
              {history.map((h, i) => (
                <div key={i} style={{ ...cardStyle, marginBottom: 8, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 13 }}>{h.target}</div>
                    <div style={{ color: COLORS.muted, fontSize: 11 }}>{h.date}</div>
                  </div>
                  <div style={{ display: "flex", gap: 8 }}>
                    <div style={{ textAlign: "center" }}>
                      <div style={{ fontFamily: "monospace", fontWeight: 700, fontSize: 20, color: h.score < 50 ? COLORS.red : h.score < 75 ? COLORS.orange : COLORS.green }}>{h.score}</div>
                      <div style={{ fontSize: 10, color: COLORS.muted }}>score</div>
                    </div>
                    {badge(h.risk, severityColor(h.risk))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── TAB: GUIDE ───────────────────────────────────────────────────── */}
      {activeTab === "guide" && (
        <div>
          <div style={cardStyle}>
            <div style={{ color: COLORS.cyan, fontWeight: 700, marginBottom: 14, fontSize: 13, fontFamily: "monospace" }}>
              📖 GUIDE D'UTILISATION — UIT SECURITY AI
            </div>
            {[
              {
                icon: "🔍", title: "Scanner de Sécurité",
                content: "Sélectionnez une cible parmi les systèmes de l'UIT (Portail, E-Learning, RH...), choisissez les vérifications OWASP à effectuer, puis lancez l'analyse. L'IA génère un rapport complet avec score de sécurité, failles détectées et recommandations."
              },
              {
                icon: "🎓", title: "Entraînement IA",
                content: "Générez des jeux de données étiquetés pour entraîner votre propre modèle de détection. Chaque exemple inclut une requête HTTP simulée, son étiquette (VULNÉRABLE/SAIN) et une explication pédagogique. Exportez en JSON pour scikit-learn ou TensorFlow."
              },
              {
                icon: "⚠️", title: "Avertissement Éthique",
                content: "Cet outil est strictement éducatif. Il simule des analyses de sécurité basées sur les vulnérabilités OWASP identifiées dans le rapport UIT 2025-2026. Aucun test réel n'est effectué sur les serveurs. Tout audit réel nécessite une autorisation écrite de la DSI."
              },
              {
                icon: "📋", title: "Standards de Conformité",
                content: "L'analyse couvre OWASP Top 10 2021, RGPD (règlement EU), Loi 09-08 du Maroc (protection des données personnelles), NIST Cybersecurity Framework et les recommandations ISO/IEC 27001:2022 applicables au contexte universitaire."
              },
            ].map((g, i) => (
              <div key={i} style={{ marginBottom: 14, padding: 14, background: COLORS.surface, borderRadius: 8 }}>
                <div style={{ fontWeight: 700, marginBottom: 6, fontSize: 14 }}>{g.icon} {g.title}</div>
                <div style={{ fontSize: 13, color: COLORS.muted, lineHeight: 1.6 }}>{g.content}</div>
              </div>
            ))}
          </div>

          {/* OWASP Reference */}
          <div style={cardStyle}>
            <div style={{ color: COLORS.cyan, fontWeight: 700, marginBottom: 14, fontSize: 13, fontFamily: "monospace" }}>
              📚 RÉFÉRENCE OWASP TOP 10 — CONTEXTE UIT
            </div>
            {OWASP_CHECKS.map(c => (
              <div key={c.id} style={{ borderBottom: `1px solid ${COLORS.dim}`, paddingBottom: 12, marginBottom: 12 }}>
                <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
                  <span style={{ fontFamily: "monospace", fontSize: 11, color: COLORS.muted }}>{c.id}</span>
                  <span style={{ fontWeight: 600, fontSize: 13 }}>{c.name}</span>
                  {badge(c.severity, severityColor(c.severity))}
                </div>
                <div style={{ fontSize: 12, color: COLORS.muted, marginBottom: 4 }}>{c.description}</div>
                <div style={{ fontSize: 11, color: COLORS.green }}>✅ {c.fix}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Footer */}
      <div style={{ textAlign: "center", marginTop: 28, color: COLORS.muted, fontSize: 11, fontFamily: "monospace" }}>
        SECURIT-AI · Université Ibn Tofail · Département Informatique · Pr. Younes Chihab · 2025-2026
        <br />⚠️ Outil pédagogique — Analyses simulées uniquement — Autorisation DSI requise pour audits réels
      </div>
    </div>
  );
}
