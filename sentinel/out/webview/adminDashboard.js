"use strict";
/**
 * Sentinel — Administrator Dashboard
 *
 * System-wide control panel for administrators.
 * Shows: all users, system stats, user management (add/remove), config viewer.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildAdminDashboardHtml = buildAdminDashboardHtml;
const loginView_js_1 = require("./loginView.js");
const supervisorDashboard_js_1 = require("./supervisorDashboard.js");
// ─── Administrator Dashboard HTML ─────────────────────────────────────────────
function buildAdminDashboardHtml(session, users, dataDir, cspSource, logoUri, extensionVersion, backendUrl) {
    const devStats = (0, supervisorDashboard_js_1.loadAllDeveloperStats)(dataDir);
    const totalFindings = devStats.reduce((s, d) => s + d.total, 0);
    const totalCritical = devStats.reduce((s, d) => s + d.critical, 0);
    const avgScore = devStats.length > 0
        ? Math.round(devStats.reduce((s, d) => s + d.score, 0) / devStats.length) : 100;
    const roleColors = {
        administrator: '#f47067',
        supervisor: '#d29922',
        developer: '#58a6ff',
    };
    const roleIcons = {
        administrator: '🔐',
        supervisor: '👁️',
        developer: '🧑‍💻',
    };
    // User rows
    const userRows = users.map(u => {
        const roleColor = roleColors[u.role] ?? '#8b949e';
        const roleIcon = roleIcons[u.role] ?? '👤';
        const created = new Date(u.createdAt).toLocaleDateString();
        const devStat = devStats.find(d => d.developerId === u.username);
        const findingsCount = devStat?.total ?? 0;
        return `<tr class="user-row" id="urow-${escHtml(u.id)}">
      <td class="td-avatar"><div class="uavatar">${u.displayName.charAt(0).toUpperCase()}</div></td>
      <td>
        <div class="u-name">${escHtml(u.displayName)}</div>
        <div class="u-username">@${escHtml(u.username)}</div>
      </td>
      <td><span class="role-badge" style="background:${roleColor}18;color:${roleColor};border-color:${roleColor}35">${roleIcon} ${u.role}</span></td>
      <td class="td-email">${escHtml(u.email)}</td>
      <td class="td-findings">${findingsCount > 0 ? `<span style="color:${findingsCount > 50 ? '#f47067' : '#8b949e'}">${findingsCount}</span>` : '<span style="color:#484f58">—</span>'}</td>
      <td class="td-date">${created}</td>
      <td>
        ${u.id !== session.userId ? `<button class="btn-remove" onclick="removeUser('${escHtml(u.id)}','${escHtml(u.username)}')">Remove</button>` : '<span class="self-label">You</span>'}
      </td>
    </tr>`;
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
<title>Sentinel — Administrator Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;line-height:1.6;min-height:100vh}
.hero{background:linear-gradient(135deg,#0d1117 0%,#1f1b2e 55%,#161b22 100%);border-bottom:1px solid rgba(255,255,255,.08);padding:16px 22px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
.brand{display:flex;align-items:center;gap:10px}
.logo-img{width:34px;height:34px;object-fit:contain;border-radius:8px}
.logo-box{width:34px;height:34px;background:linear-gradient(135deg,#f47067,#b91c1c);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:17px}
.bname{font-size:1.2em;font-weight:800;letter-spacing:-.3px}
.bsub{font-size:.63em;font-weight:500;color:#8b949e;text-transform:uppercase;letter-spacing:1.2px}
.admin-badge{display:flex;align-items:center;gap:5px;background:rgba(244,112,103,.12);border:1px solid rgba(244,112,103,.25);border-radius:100px;padding:4px 10px;font-size:.65em;color:#f47067;font-weight:600}
.wrap{padding:18px 22px}
/* KPI strip */
.kpi-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:10px;margin-bottom:20px}
.kpi{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:11px;padding:14px 13px;transition:border-color .2s,transform .15s}
.kpi:hover{border-color:rgba(255,255,255,.15);transform:translateY(-2px)}
.kpi-ico{font-size:.9em;margin-bottom:4px}
.kpi-num{font-size:1.75em;font-weight:800;line-height:1;letter-spacing:-1px}
.kpi-lbl{font-size:.6em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.7px;margin-top:3px}
/* Section */
.section{background:#161b22;border:1px solid rgba(255,255,255,.08);border-radius:13px;margin-bottom:20px;overflow:hidden}
.sec-hdr{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid rgba(255,255,255,.07);flex-wrap:wrap;gap:8px}
.sec-title{font-size:.75em;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#8b949e}
.sec-body{padding:16px 18px}
/* Users table */
.user-table{width:100%;border-collapse:collapse;font-size:.8em}
.user-table th{font-size:.65em;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#484f58;padding:6px 10px;text-align:left;border-bottom:1px solid rgba(255,255,255,.06)}
.user-row td{padding:10px 10px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle}
.user-row:last-child td{border-bottom:none}
.user-row:hover{background:rgba(255,255,255,.02)}
.td-avatar{width:40px}
.uavatar{width:30px;height:30px;border-radius:50%;background:linear-gradient(135deg,#1f6feb,#388bfd);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.8em;color:#fff;line-height:30px;text-align:center}
.u-name{font-weight:600;color:#e6edf3;font-size:.88em}
.u-username{font-size:.72em;color:#484f58}
.role-badge{display:inline-block;padding:3px 9px;border-radius:100px;font-size:.72em;font-weight:600;border:1px solid;white-space:nowrap}
.td-email{color:#8b949e;font-size:.78em}
.td-findings,.td-date{color:#8b949e;font-size:.78em;text-align:center}
.btn-remove{background:rgba(244,112,103,.1);border:1px solid rgba(244,112,103,.25);border-radius:6px;padding:4px 9px;font-size:.72em;font-weight:600;color:#f47067;cursor:pointer;font-family:inherit;transition:background .15s}
.btn-remove:hover{background:rgba(244,112,103,.22)}
.self-label{font-size:.72em;color:#484f58;font-style:italic}
/* Add user form */
.add-form{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;align-items:end}
.fg{display:flex;flex-direction:column;gap:4px}
label{font-size:.68em;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.5px}
input,select{background:rgba(13,17,23,.8);border:1px solid rgba(255,255,255,.1);border-radius:8px;padding:8px 11px;color:#e6edf3;font-size:.82em;font-family:inherit;outline:none;transition:border-color .2s}
input:focus,select:focus{border-color:rgba(88,166,255,.45);box-shadow:0 0 0 2px rgba(88,166,255,.1)}
input::placeholder{color:#484f58}
select option{background:#161b22;color:#e6edf3}
.btn-add{background:linear-gradient(135deg,#1f6feb,#388bfd);border:none;border-radius:8px;padding:9px 16px;color:#fff;font-size:.82em;font-weight:700;font-family:inherit;cursor:pointer;white-space:nowrap;transition:opacity .2s,transform .12s}
.btn-add:hover{opacity:.9;transform:translateY(-1px)}
.msg{display:none;padding:8px 12px;border-radius:7px;font-size:.78em;font-weight:600;margin-top:10px}
.msg.ok{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.25);color:#3fb950;display:block}
.msg.err{background:rgba(244,112,103,.1);border:1px solid rgba(244,112,103,.25);color:#f47067;display:block}
/* Config */
.cfg-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.cfg-item{background:#0d1117;border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:10px 13px}
.cfg-key{font-size:.65em;font-weight:700;text-transform:uppercase;letter-spacing:.7px;color:#484f58;margin-bottom:3px}
.cfg-val{font-size:.82em;color:#e6edf3;font-family:'Courier New',monospace}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:3px}
@media(max-width:600px){.add-form{grid-template-columns:1fr}.cfg-grid{grid-template-columns:1fr}.td-email,.td-date{display:none}}
</style>
</head>
<body>
${(0, loginView_js_1.buildHeaderBar)(session, cspSource)}
<div class="hero">
  <div class="brand">
    ${logoEl}
    <div>
      <div class="bname">Sentinel</div>
      <div class="bsub">Administrator Dashboard</div>
    </div>
  </div>
  <div class="admin-badge">🔐 Full System Access</div>
</div>
<div class="wrap">
  <!-- KPIs -->
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-ico">👥</div><div class="kpi-num" style="color:#58a6ff">${users.length}</div><div class="kpi-lbl">Total Users</div></div>
    <div class="kpi"><div class="kpi-ico">🧑‍💻</div><div class="kpi-num" style="color:#58a6ff">${users.filter(u => u.role === 'developer').length}</div><div class="kpi-lbl">Developers</div></div>
    <div class="kpi"><div class="kpi-ico">👁️</div><div class="kpi-num" style="color:#d29922">${users.filter(u => u.role === 'supervisor').length}</div><div class="kpi-lbl">Supervisors</div></div>
    <div class="kpi"><div class="kpi-ico">🔐</div><div class="kpi-num" style="color:#f47067">${users.filter(u => u.role === 'administrator').length}</div><div class="kpi-lbl">Admins</div></div>
    <div class="kpi"><div class="kpi-ico">📋</div><div class="kpi-num">${totalFindings}</div><div class="kpi-lbl">All Findings</div></div>
    <div class="kpi"><div class="kpi-ico">🚨</div><div class="kpi-num" style="color:#f47067">${totalCritical}</div><div class="kpi-lbl">Critical</div></div>
    <div class="kpi"><div class="kpi-ico">⭐</div><div class="kpi-num" style="color:${avgScore >= 80 ? '#3fb950' : avgScore >= 50 ? '#d29922' : '#f47067'}">${avgScore}</div><div class="kpi-lbl">Avg Score</div></div>
  </div>

  <!-- User Management Table -->
  <div class="section">
    <div class="sec-hdr">
      <span class="sec-title">👥 User Management</span>
    </div>
    <div id="tableMsg" class="msg"></div>
    <div style="overflow-x:auto">
      <table class="user-table" id="userTable">
        <thead>
          <tr>
            <th></th>
            <th>User</th>
            <th>Role</th>
            <th>Email</th>
            <th style="text-align:center">Findings</th>
            <th style="text-align:center">Joined</th>
            <th></th>
          </tr>
        </thead>
        <tbody id="userTbody">
          ${userRows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Add User Form -->
  <div class="section">
    <div class="sec-hdr">
      <span class="sec-title">➕ Add New User</span>
    </div>
    <div class="sec-body">
      <div class="add-form">
        <div class="fg">
          <label for="newUsername">Username</label>
          <input id="newUsername" type="text" placeholder="e.g. dev03">
        </div>
        <div class="fg">
          <label for="newPassword">Password</label>
          <input id="newPassword" type="password" placeholder="Min 6 characters">
        </div>
        <div class="fg">
          <label for="newDisplayName">Display Name</label>
          <input id="newDisplayName" type="text" placeholder="e.g. Charlie (Dev)">
        </div>
        <div class="fg">
          <label for="newEmail">Email</label>
          <input id="newEmail" type="email" placeholder="user@domain.com">
        </div>
        <div class="fg">
          <label for="newRole">Role</label>
          <select id="newRole">
            <option value="developer">🧑‍💻 Developer</option>
            <option value="supervisor">👁️ Supervisor</option>
            <option value="administrator">🔐 Administrator</option>
          </select>
        </div>
        <div class="fg">
          <label>&nbsp;</label>
          <button class="btn-add" onclick="addUser()">Add User</button>
        </div>
      </div>
      <div id="addMsg" class="msg"></div>
    </div>
  </div>

  <!-- System Config -->
  <div class="section">
    <div class="sec-hdr">
      <span class="sec-title">⚙️ System Configuration</span>
    </div>
    <div class="sec-body">
      <div class="cfg-grid">
        <div class="cfg-item"><div class="cfg-key">Extension Version</div><div class="cfg-val">${escHtml(extensionVersion)}</div></div>
        <div class="cfg-item"><div class="cfg-key">Backend API URL</div><div class="cfg-val">${escHtml(backendUrl)}</div></div>
        <div class="cfg-item"><div class="cfg-key">Data Directory</div><div class="cfg-val">${escHtml(dataDir)}</div></div>
        <div class="cfg-item"><div class="cfg-key">Total Developer Record Files</div><div class="cfg-val">${devStats.length}</div></div>
      </div>
    </div>
  </div>
</div>

<script>
const vscode = acquireVsCodeApi();

function showMsg(id, type, text) {
  var el = document.getElementById(id);
  el.className = 'msg ' + type;
  el.textContent = text;
  setTimeout(function(){ el.className = 'msg'; }, 4000);
}

function addUser() {
  var username = document.getElementById('newUsername').value.trim();
  var password = document.getElementById('newPassword').value;
  var displayName = document.getElementById('newDisplayName').value.trim();
  var email = document.getElementById('newEmail').value.trim();
  var role = document.getElementById('newRole').value;
  if (!username || !password || !displayName || !email) {
    showMsg('addMsg', 'err', 'Please fill in all fields.');
    return;
  }
  if (password.length < 6) {
    showMsg('addMsg', 'err', 'Password must be at least 6 characters.');
    return;
  }
  vscode.postMessage({ command: 'ADMIN_ADD_USER', username, password, displayName, email, role });
}

function removeUser(userId, username) {
  if (!confirm('Remove user "' + username + '"? This cannot be undone.')) { return; }
  vscode.postMessage({ command: 'ADMIN_REMOVE_USER', userId, username });
}

window.addEventListener('message', function(event) {
  var msg = event.data;
  if (msg.command === 'ADMIN_USER_RESULT') {
    if (msg.success) {
      showMsg('tableMsg', 'ok', msg.message);
      // Refresh the dashboard to reflect changes
      setTimeout(function(){ vscode.postMessage({ command: 'REFRESH_ADMIN' }); }, 1200);
    } else {
      showMsg('tableMsg', 'err', msg.message);
    }
  }
  if (msg.command === 'ADMIN_ADD_RESULT') {
    if (msg.success) {
      showMsg('addMsg', 'ok', msg.message);
      document.getElementById('newUsername').value = '';
      document.getElementById('newPassword').value = '';
      document.getElementById('newDisplayName').value = '';
      document.getElementById('newEmail').value = '';
      setTimeout(function(){ vscode.postMessage({ command: 'REFRESH_ADMIN' }); }, 1200);
    } else {
      showMsg('addMsg', 'err', msg.message);
    }
  }
});
</script>
</body>
</html>`;
}
function escHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
//# sourceMappingURL=adminDashboard.js.map