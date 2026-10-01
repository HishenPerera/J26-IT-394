"use strict";
/**
 * Sentinel — Supervisor Dashboard
 *
 * Team-level security overview for supervisors.
 * Reads all developer record files from src/DATA/ to aggregate team stats.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadAllDeveloperStats = loadAllDeveloperStats;
exports.buildSupervisorDashboardHtml = buildSupervisorDashboardHtml;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const loginView_js_1 = require("./loginView.js");
// ─── Data loader ─────────────────────────────────────────────────────────────
function loadAllDeveloperStats(dataDir) {
    const stats = [];
    try {
        if (!fs.existsSync(dataDir)) {
            return [];
        }
        const files = fs.readdirSync(dataDir).filter(f => f.endsWith('_vulnerability_records.json'));
        for (const file of files) {
            const devId = file.replace('_vulnerability_records.json', '');
            try {
                const raw = fs.readFileSync(path.join(dataDir, file), 'utf8');
                const records = JSON.parse(raw);
                if (!Array.isArray(records) || records.length === 0) {
                    continue;
                }
                let critical = 0, high = 0, medium = 0, low = 0;
                const typeBreakdown = {};
                let lastSeen = records[0].detectedAt;
                for (const r of records) {
                    if (r.severity === 'CRITICAL') {
                        critical++;
                    }
                    else if (r.severity === 'HIGH') {
                        high++;
                    }
                    else if (r.severity === 'MEDIUM') {
                        medium++;
                    }
                    else {
                        low++;
                    }
                    typeBreakdown[r.vulnerabilityType] = (typeBreakdown[r.vulnerabilityType] ?? 0) + 1;
                    if (r.detectedAt > lastSeen) {
                        lastSeen = r.detectedAt;
                    }
                }
                const total = records.length;
                const score = Math.max(0, 100 - (critical * 25 + high * 10 + medium * 5 + low * 2));
                stats.push({ developerId: devId, total, critical, high, medium, low, score, lastSeen, typeBreakdown });
            }
            catch { /* skip corrupt files */ }
        }
    }
    catch { /* skip if DATA dir missing */ }
    // Sort by score descending (best developers first)
    return stats.sort((a, b) => b.score - a.score);
}
// ─── Supervisor Dashboard HTML ────────────────────────────────────────────────
function buildSupervisorDashboardHtml(session, dataDir, cspSource, logoUri) {
    const devStats = loadAllDeveloperStats(dataDir);
    // Team aggregates
    const teamTotal = devStats.reduce((s, d) => s + d.total, 0);
    const teamCritical = devStats.reduce((s, d) => s + d.critical, 0);
    const teamHigh = devStats.reduce((s, d) => s + d.high, 0);
    const teamMedium = devStats.reduce((s, d) => s + d.medium, 0);
    const teamScore = devStats.length > 0
        ? Math.round(devStats.reduce((s, d) => s + d.score, 0) / devStats.length) : 100;
    const scoreColor = teamScore >= 80 ? '#3fb950' : teamScore >= 50 ? '#d29922' : '#f47067';
    // Global type breakdown
    const globalTypes = {};
    for (const d of devStats) {
        for (const [t, c] of Object.entries(d.typeBreakdown)) {
            globalTypes[t] = (globalTypes[t] ?? 0) + c;
        }
    }
    const maxTypeCount = Math.max(...Object.values(globalTypes), 1);
    const typeBarRows = Object.entries(globalTypes)
        .sort((a, b) => b[1] - a[1])
        .map(([type, count]) => {
        const pct = Math.round((count / maxTypeCount) * 100);
        const color = type.includes('INJECTION') ? '#f47067'
            : type.includes('XSS') ? '#f0883e'
                : '#d29922';
        return `<div class="brow">
        <span class="btype">${type.replace(/_/g, ' ')}</span>
        <div class="bbar-wrap"><div class="bbar" style="width:${pct}%;background:${color}"></div></div>
        <span class="bcount">${count}</span>
      </div>`;
    }).join('');
    // Developer ranking cards
    const devCards = devStats.length === 0
        ? `<div class="empty"><div class="eico">👥</div><div class="ettl">No developer data yet</div><div>Data will appear once developers use the extension and findings are detected.</div></div>`
        : devStats.map((d, i) => {
            const rankColor = i === 0 ? '#ffd700' : i === 1 ? '#c0c0c0' : i === 2 ? '#cd7f32' : '#8b949e';
            const scoreC = d.score >= 80 ? '#3fb950' : d.score >= 50 ? '#d29922' : '#f47067';
            const lastSeen = new Date(d.lastSeen).toLocaleDateString();
            return `<div class="dev-card">
        <div class="dev-rank" style="color:${rankColor}">#${i + 1}</div>
        <div class="dev-avatar">${d.developerId.charAt(0).toUpperCase()}</div>
        <div class="dev-info">
          <div class="dev-id">${escHtml(d.developerId)}</div>
          <div class="dev-last">Last active: ${lastSeen}</div>
        </div>
        <div class="dev-score-wrap">
          <div class="dev-score" style="color:${scoreC}">${d.score}</div>
          <div class="dev-score-lbl">score</div>
        </div>
        <div class="dev-pills">
          ${d.critical > 0 ? `<span class="dp" style="background:#f4706722;color:#f47067;border-color:#f4706744">🚨 ${d.critical}</span>` : ''}
          ${d.high > 0 ? `<span class="dp" style="background:#f0883e22;color:#f0883e;border-color:#f0883e44">🔴 ${d.high}</span>` : ''}
          ${d.medium > 0 ? `<span class="dp" style="background:#d2992222;color:#d29922;border-color:#d2992244">🟠 ${d.medium}</span>` : ''}
          <span class="dp" style="background:rgba(255,255,255,.05);color:#8b949e;border-color:rgba(255,255,255,.1)">📋 ${d.total}</span>
        </div>
      </div>`;
        }).join('');
    const logoEl = logoUri
        ? `<img src="${logoUri}" alt="Sentinel" class="logo-img">`
        : `<div class="logo-box">&#x1F6E1;</div>`;
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${cspSource} data:; script-src 'unsafe-inline';">
<title>Sentinel — Supervisor Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;line-height:1.6;min-height:100vh}
.hero{background:linear-gradient(135deg,#0d1117 0%,#1a1b2e 55%,#161b22 100%);border-bottom:1px solid rgba(255,255,255,.08);padding:16px 22px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
.brand{display:flex;align-items:center;gap:10px}
.logo-img{width:34px;height:34px;object-fit:contain;border-radius:8px}
.logo-box{width:34px;height:34px;background:linear-gradient(135deg,#d29922,#f0883e);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:17px}
.bname{font-size:1.2em;font-weight:800;letter-spacing:-.3px}
.bsub{font-size:.63em;font-weight:500;color:#8b949e;text-transform:uppercase;letter-spacing:1.2px}
.team-badge{display:flex;align-items:center;gap:5px;background:rgba(210,153,34,.12);border:1px solid rgba(210,153,34,.25);border-radius:100px;padding:4px 10px;font-size:.65em;color:#d29922;font-weight:600}
.wrap{padding:18px 22px}
/* Team score */
.team-score-bar{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:13px;padding:18px 22px;margin-bottom:18px;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.tscore-ring{position:relative;width:80px;height:80px;flex-shrink:0}
.tscore-ring svg{transform:rotate(-90deg);width:80px;height:80px}
.rbg{fill:none;stroke:rgba(255,255,255,.06);stroke-width:8}
.rfg{fill:none;stroke:${scoreColor};stroke-width:8;stroke-linecap:round;stroke-dasharray:220;stroke-dashoffset:220;animation:rng 1.2s cubic-bezier(.4,0,.2,1) forwards .15s}
@keyframes rng{to{stroke-dashoffset:${220 - (teamScore / 100) * 220}}}
.tscore-lbl{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column}
.tscore-num{font-size:1.35em;font-weight:800;color:${scoreColor};line-height:1}
.tscore-sub{font-size:.5em;color:#8b949e}
.team-title{font-size:1em;font-weight:700;color:#e6edf3;margin-bottom:2px}
.team-desc{font-size:.78em;color:#8b949e}
.team-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(80px,1fr));gap:8px;flex:1;margin-left:8px}
.kpi{background:#0d1117;border:1px solid rgba(255,255,255,.07);border-radius:9px;padding:11px 10px;text-align:center}
.kpi-num{font-size:1.5em;font-weight:800;line-height:1;letter-spacing:-1px}
.kpi-lbl{font-size:.58em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.7px;margin-top:2px}
/* Type breakdown */
.section{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:13px;padding:16px 18px;margin-bottom:18px}
.shdr{display:flex;align-items:center;gap:8px;margin-bottom:12px}
.stxt{font-size:.68em;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#8b949e}
.shdr::after{content:'';flex:1;height:1px;background:rgba(255,255,255,.08)}
.cbadge{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);border-radius:100px;font-size:.63em;font-weight:600;padding:2px 7px;color:#8b949e}
.brow{display:grid;grid-template-columns:160px 1fr 32px;align-items:center;gap:8px;padding:4px 0}
.btype{font-size:.72em;color:#e6edf3;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bbar-wrap{background:rgba(255,255,255,.05);border-radius:100px;height:6px;overflow:hidden}
.bbar{height:100%;border-radius:100px;transition:width .8s cubic-bezier(.4,0,.2,1)}
.bcount{font-size:.7em;font-weight:700;color:#8b949e;text-align:right}
/* Developer cards */
.dev-card{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:11px;padding:14px 16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;transition:border-color .2s,transform .15s}
.dev-card:hover{border-color:rgba(255,255,255,.16);transform:translateY(-1px)}
.dev-rank{font-size:1em;font-weight:800;min-width:26px;text-align:center}
.dev-avatar{width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#1f6feb,#388bfd);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.9em;color:#fff;flex-shrink:0}
.dev-info{flex:1;min-width:80px}
.dev-id{font-size:.86em;font-weight:700;color:#e6edf3}
.dev-last{font-size:.65em;color:#484f58;margin-top:1px}
.dev-score-wrap{text-align:center;min-width:40px}
.dev-score{font-size:1.5em;font-weight:800;line-height:1;letter-spacing:-1px}
.dev-score-lbl{font-size:.58em;color:#8b949e}
.dev-pills{display:flex;gap:5px;flex-wrap:wrap}
.dp{display:inline-flex;align-items:center;gap:3px;padding:2px 7px;border-radius:100px;font-size:.65em;font-weight:600;border:1px solid}
.dev-list{display:flex;flex-direction:column;gap:8px}
.empty{text-align:center;padding:40px 20px;color:#8b949e}
.eico{font-size:2.5em;margin-bottom:8px}
.ettl{font-size:.95em;font-weight:700;color:#d29922;margin-bottom:4px}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:3px}
@media(max-width:540px){.brow{grid-template-columns:120px 1fr 28px}.team-kpis{margin-left:0}}
</style>
</head>
<body>
${(0, loginView_js_1.buildHeaderBar)(session, cspSource)}
<div class="hero">
  <div class="brand">
    ${logoEl}
    <div>
      <div class="bname">Sentinel</div>
      <div class="bsub">Supervisor Dashboard</div>
    </div>
  </div>
  <div class="team-badge">👥 ${devStats.length} Developer${devStats.length !== 1 ? 's' : ''} Monitored</div>
</div>
<div class="wrap">
  <div class="team-score-bar">
    <div class="tscore-ring">
      <svg viewBox="0 0 80 80">
        <circle class="rbg" cx="40" cy="40" r="35"/>
        <circle class="rfg" cx="40" cy="40" r="35"/>
      </svg>
      <div class="tscore-lbl">
        <span class="tscore-num">${teamScore}</span>
        <span class="tscore-sub">/ 100</span>
      </div>
    </div>
    <div>
      <div class="team-title">Team Security Score</div>
      <div class="team-desc">Average across ${devStats.length} developer${devStats.length !== 1 ? 's' : ''}</div>
    </div>
    <div class="team-kpis">
      <div class="kpi"><div class="kpi-num" style="color:#f47067">${teamCritical}</div><div class="kpi-lbl">Critical</div></div>
      <div class="kpi"><div class="kpi-num" style="color:#f0883e">${teamHigh}</div><div class="kpi-lbl">High</div></div>
      <div class="kpi"><div class="kpi-num" style="color:#d29922">${teamMedium}</div><div class="kpi-lbl">Medium</div></div>
      <div class="kpi"><div class="kpi-num">${teamTotal}</div><div class="kpi-lbl">Total</div></div>
    </div>
  </div>

  ${Object.keys(globalTypes).length > 0 ? `
  <div class="section">
    <div class="shdr"><span class="stxt">Team Vulnerability Breakdown</span></div>
    ${typeBarRows}
  </div>` : ''}

  <div class="shdr"><span class="stxt">Developer Rankings</span><span class="cbadge">${devStats.length}</span></div>
  <div class="dev-list">${devCards}</div>
</div>
</body>
</html>`;
}
function escHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
//# sourceMappingURL=supervisorDashboard.js.map