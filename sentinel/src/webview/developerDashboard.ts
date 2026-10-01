/**
 * Sentinel — Developer Dashboard
 *
 * Personal security dashboard for the logged-in developer.
 * Shows: security score, live findings, vuln breakdown, session stats.
 */

import { SecurityFinding } from '../analyzer/types.js';
import { AuthSession } from '../auth/authManager.js';
import { generateContextualExplanation } from '../diagnostics/contextualExplainer.js';
import { buildHeaderBar } from './loginView.js';

// ─── Developer Dashboard ─────────────────────────────────────────────────────

export function buildDeveloperDashboardHtml(
  summary: any,
  findings: SecurityFinding[],
  session: AuthSession,
  logoUri: string,
  cspSource: string,
  rulesCount: number,
  sessionId: string,
): string {
  const scoreRaw = findings.length === 0 ? 100
    : Math.max(0, 100 - (summary.criticalCount * 25 + summary.highCount * 10 + summary.mediumCount * 5 + summary.lowCount * 2));
  const scoreColor = scoreRaw >= 80 ? '#3fb950' : scoreRaw >= 50 ? '#d29922' : '#f47067';
  const circumference = 283;
  const dashOffset = circumference - (scoreRaw / 100) * circumference;

  // Vuln type breakdown
  const typeMap: Record<string, number> = {};
  for (const f of findings) {
    typeMap[f.type] = (typeMap[f.type] ?? 0) + 1;
  }
  const typeRows = Object.entries(typeMap)
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => {
      const pct = Math.round((count / findings.length) * 100);
      const color = type.includes('INJECTION') ? '#f47067'
        : type.includes('XSS') ? '#f0883e'
        : '#d29922';
      return `<div class="brow">
        <span class="btype">${type.replace(/_/g, ' ')}</span>
        <div class="bbar-wrap"><div class="bbar" style="width:${pct}%;background:${color}"></div></div>
        <span class="bcount">${count}</span>
      </div>`;
    }).join('');

  // Finding cards
  const findingCards = findings.map(f => {
    const ctx = generateContextualExplanation(f);
    const conf = Math.round(f.confidence * 100);
    const sevColor = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? '#f47067'
      : f.severity === 'MEDIUM' ? '#d29922' : '#3fb950';
    const sevIcon = f.severity === 'CRITICAL' ? '&#x1F6A8;'
      : f.severity === 'HIGH' ? '&#x1F534;'
      : f.severity === 'MEDIUM' ? '&#x1F7E0;' : '&#x1F7E1;';
    return `
<div class="card" id="card-${f.id}">
  <div class="card-hdr" onclick="tog('${f.id}')">
    <div class="lft">
      <span class="pill" style="background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}44">${sevIcon} ${f.severity}</span>
      <div>
        <div class="ctitle">${f.type.replace(/_/g, ' ')}</div>
        <div class="cfile">&#x1F4C4; ${escHtml(f.fileName.split('/').pop() ?? '')} &middot; Line ${f.lineNumber}</div>
      </div>
    </div>
    <div class="rgt">
      <span class="conf">${conf}%</span>
      <span class="chev" id="chev-${f.id}">&#9660;</span>
    </div>
  </div>
  <div class="chl">${escHtml(ctx.headline)}</div>
  <div class="cbody" id="body-${f.id}">
    <div class="dlbl">Why is this vulnerable?</div>
    <div class="dtxt">${escHtml(ctx.whyDangerous)}</div>
    <div class="cmp">
      <div><div class="clbl dlbl-d">Vulnerable code</div><pre class="pre-d">${escHtml(ctx.vulnerableCode)}</pre></div>
      <div><div class="clbl dlbl-s">Fixed version</div><pre class="pre-s">${escHtml(ctx.fixedCode)}</pre></div>
    </div>
    <div class="dlbl">Attack scenario</div>
    <div class="atk">${escHtml(ctx.attackScenario)}</div>
    <div class="fix">&#x1F4A1; ${escHtml(ctx.fixExplanation)}</div>
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
<title>Sentinel — Developer Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;line-height:1.6;min-height:100vh}
.hero{background:linear-gradient(135deg,#0d1117 0%,#161b22 55%,#1a1f2e 100%);border-bottom:1px solid rgba(255,255,255,.08);padding:16px 22px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
.brand{display:flex;align-items:center;gap:10px}
.logo-img{width:34px;height:34px;object-fit:contain;border-radius:8px}
.logo-box{width:34px;height:34px;background:linear-gradient(135deg,#1f6feb,#388bfd);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:17px;box-shadow:0 0 12px rgba(88,166,255,.3)}
.bname{font-size:1.2em;font-weight:800;letter-spacing:-.3px}
.bsub{font-size:.63em;font-weight:500;color:#8b949e;text-transform:uppercase;letter-spacing:1.2px}
.sess{display:flex;align-items:center;gap:5px;background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.22);border-radius:100px;padding:4px 10px;font-size:.65em;color:#58a6ff;font-family:'Courier New',monospace}
.dot{width:5px;height:5px;border-radius:50%;background:#3fb950;box-shadow:0 0 5px #3fb950;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.wrap{padding:18px 22px}
.mrow{display:grid;grid-template-columns:auto 1fr;gap:12px;margin-bottom:22px;align-items:stretch}
.scard{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:13px;padding:18px 20px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;min-width:140px}
.rw{position:relative;width:100px;height:100px}
.rw svg{transform:rotate(-90deg);width:100px;height:100px}
.rbg{fill:none;stroke:rgba(255,255,255,.06);stroke-width:9}
.rfg{fill:none;stroke:${scoreColor};stroke-width:9;stroke-linecap:round;stroke-dasharray:${circumference};stroke-dashoffset:${circumference};animation:rng 1.2s cubic-bezier(.4,0,.2,1) forwards .15s}
@keyframes rng{to{stroke-dashoffset:${dashOffset}}}
.rlbl{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column}
.rnum{font-size:1.55em;font-weight:800;color:${scoreColor};line-height:1}
.rsub{font-size:.55em;color:#8b949e;font-weight:500}
.sttl{font-size:.63em;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#8b949e}
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(88px,1fr));gap:8px}
.stat{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:11px;padding:13px 11px;display:flex;flex-direction:column;gap:4px;transition:border-color .2s,transform .15s;cursor:default}
.stat:hover{border-color:rgba(255,255,255,.15);transform:translateY(-2px)}
.sico{font-size:.9em}
.snum{font-size:1.75em;font-weight:800;line-height:1;letter-spacing:-1px}
.slbl{font-size:.6em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.7px}
/* Breakdown */
.section{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:13px;padding:16px 18px;margin-bottom:18px}
.shdr{display:flex;align-items:center;gap:8px;margin-bottom:12px}
.stxt{font-size:.68em;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#8b949e}
.shdr::after{content:'';flex:1;height:1px;background:rgba(255,255,255,.08)}
.cbadge{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);border-radius:100px;font-size:.63em;font-weight:600;padding:2px 7px;color:#8b949e}
.brow{display:grid;grid-template-columns:140px 1fr 30px;align-items:center;gap:8px;padding:4px 0}
.btype{font-size:.72em;color:#e6edf3;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bbar-wrap{background:rgba(255,255,255,.05);border-radius:100px;height:6px;overflow:hidden}
.bbar{height:100%;border-radius:100px;transition:width .8s cubic-bezier(.4,0,.2,1)}
.bcount{font-size:.7em;font-weight:700;color:#8b949e;text-align:right}
/* Cards */
.cards{display:flex;flex-direction:column;gap:8px}
.card{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:11px;overflow:hidden;transition:border-color .2s,box-shadow .2s,transform .15s}
.card:hover{border-color:rgba(255,255,255,.15);box-shadow:0 4px 16px rgba(0,0,0,.3);transform:translateY(-1px)}
.card-hdr{display:flex;align-items:center;justify-content:space-between;padding:11px 14px;cursor:pointer;user-select:none;background:#1c2128;transition:background .15s}
.card-hdr:hover{background:rgba(255,255,255,.04)}
.lft{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.rgt{display:flex;align-items:center;gap:6px;flex-shrink:0}
.pill{padding:3px 8px;border-radius:100px;font-size:9px;font-weight:700;letter-spacing:.5px;white-space:nowrap}
.ctitle{font-weight:700;font-size:.84em}
.cfile{font-size:.67em;color:#8b949e;margin-top:1px}
.conf{font-size:.66em;font-weight:600;color:#8b949e;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);border-radius:100px;padding:2px 6px}
.chev{font-size:9px;color:#484f58;transition:transform .22s ease;display:inline-block}
.chev.open{transform:rotate(180deg)}
.chl{padding:7px 14px 9px;font-size:.77em;color:#8b949e;border-top:1px solid rgba(255,255,255,.08)}
.cbody{display:none;padding:14px;border-top:1px solid rgba(255,255,255,.08);background:#0d1117}
.cbody.open{display:block;animation:sl .18s ease}
@keyframes sl{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
.dlbl{font-size:.63em;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#8b949e;margin-bottom:5px;margin-top:11px}
.dlbl:first-child{margin-top:0}
.dtxt{font-size:.82em}
.cmp{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:8px 0 2px}
.clbl{font-size:.6em;font-weight:700;letter-spacing:.7px;text-transform:uppercase;padding:4px 9px;border-radius:5px 5px 0 0}
.dlbl-d{background:rgba(244,112,103,.12);color:#f47067}
.dlbl-s{background:rgba(63,185,80,.1);color:#3fb950}
pre{font-family:'Cascadia Code','Fira Code','Courier New',monospace;font-size:10.5px;padding:9px 10px;background:rgba(0,0,0,.35);border-radius:0 0 5px 5px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
.pre-d{border:1px solid rgba(244,112,103,.22);border-top:none}
.pre-s{border:1px solid rgba(63,185,80,.17);border-top:none}
.atk{background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.2);border-radius:7px;padding:8px 10px;font-size:.77em;white-space:pre-wrap;font-family:'Cascadia Code','Fira Code','Courier New',monospace;color:#d29922}
.fix{background:rgba(63,185,80,.07);border:1px solid rgba(63,185,80,.16);border-radius:7px;padding:8px 10px;font-size:.8em;color:#3fb950;margin-top:8px}
.empty{text-align:center;padding:48px 20px;color:#8b949e}
.eico{font-size:2.8em;margin-bottom:10px;filter:drop-shadow(0 0 14px rgba(63,185,80,.5))}
.ettl{font-size:.98em;font-weight:700;color:#3fb950;margin-bottom:4px}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:3px}
@media(max-width:560px){.mrow{grid-template-columns:1fr}.cmp{grid-template-columns:1fr}}
</style>
</head>
<body>
${buildHeaderBar(session, cspSource)}
<div class="hero">
  <div class="brand">
    ${logoEl}
    <div>
      <div class="bname">Sentinel</div>
      <div class="bsub">Developer Dashboard</div>
    </div>
  </div>
  <div class="sess"><span class="dot"></span>${escHtml(sessionId)}</div>
</div>
<div class="wrap">
  <div class="mrow">
    <div class="scard">
      <div class="rw">
        <svg viewBox="0 0 100 100">
          <circle class="rbg" cx="50" cy="50" r="45"/>
          <circle class="rfg" cx="50" cy="50" r="45"/>
        </svg>
        <div class="rlbl">
          <span class="rnum">${scoreRaw}</span>
          <span class="rsub">/ 100</span>
        </div>
      </div>
      <div class="sttl">Security Score</div>
    </div>
    <div class="sgrid">
      <div class="stat"><div class="sico">&#x1F6A8;</div><div class="snum" style="color:#f47067">${summary.criticalCount}</div><div class="slbl">Critical</div></div>
      <div class="stat"><div class="sico">&#x1F534;</div><div class="snum" style="color:#f0883e">${summary.highCount}</div><div class="slbl">High</div></div>
      <div class="stat"><div class="sico">&#x1F7E0;</div><div class="snum" style="color:#d29922">${summary.mediumCount}</div><div class="slbl">Medium</div></div>
      <div class="stat"><div class="sico">&#x1F7E1;</div><div class="snum" style="color:#3fb950">${summary.lowCount ?? 0}</div><div class="slbl">Low</div></div>
      <div class="stat"><div class="sico">&#x1F4CB;</div><div class="snum">${summary.totalFindings}</div><div class="slbl">Total</div></div>
      <div class="stat"><div class="sico">&#x2699;&#xFE0F;</div><div class="snum" style="color:#58a6ff">${rulesCount}</div><div class="slbl">Rules</div></div>
    </div>
  </div>

  ${Object.keys(typeMap).length > 0 ? `
  <div class="section">
    <div class="shdr"><span class="stxt">Vulnerability Breakdown</span></div>
    ${typeRows}
  </div>` : ''}

  <div class="shdr"><span class="stxt">Detected Vulnerabilities</span><span class="cbadge">${findings.length}</span></div>
  ${findings.length === 0
    ? `<div class="empty"><div class="eico">&#x2705;</div><div class="ettl">All Clear</div><div>No vulnerabilities detected in open files.</div></div>`
    : `<div class="cards">${findingCards}</div>`}
</div>
<script>
function tog(id){
  var b=document.getElementById('body-'+id),c=document.getElementById('chev-'+id);
  if(!b||!c)return;
  var o=b.classList.contains('open');
  b.classList.toggle('open',!o);
  c.classList.toggle('open',!o);
}
var h=document.querySelector('.card-hdr');
if(h){var el=h.parentElement;if(el&&el.id)tog(el.id.replace('card-',''));}
</script>
</body>
</html>`;
}

function escHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
