/**
 * Sentinel — Login View HTML Builder
 *
 * Renders a glassmorphism dark login card that matches the existing
 * Sentinel dashboard aesthetic. Communicates back to the extension
 * host via vscode.postMessage.
 */

import { AuthSession } from '../auth/authManager.js';

// ─── Login Screen ─────────────────────────────────────────────────────────────

export function buildLoginHtml(cspSource: string, logoUri: string = '', errorMessage: string = ''): string {
  const logo = logoUri
    ? `<img src="${logoUri}" alt="Sentinel" class="logo-img">`
    : `<div class="logo-box">🛡</div>`;

  const errorBlock = errorMessage
    ? `<div class="error-msg"><span>⚠</span> ${escHtml(errorMessage)}</div>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src ${cspSource} data:; script-src 'unsafe-inline';">
<title>Sentinel — Login</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Inter',system-ui,sans-serif;
  background:#0d1117;
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  position:relative;
  overflow:hidden;
}
/* Background grid */
body::before{
  content:'';
  position:fixed;
  inset:0;
  background-image:
    linear-gradient(rgba(88,166,255,.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(88,166,255,.04) 1px, transparent 1px);
  background-size:44px 44px;
  pointer-events:none;
}
/* Ambient glows */
.glow-tl{position:fixed;top:-120px;left:-120px;width:480px;height:480px;background:radial-gradient(circle,rgba(31,111,235,.18) 0%,transparent 70%);pointer-events:none}
.glow-br{position:fixed;bottom:-100px;right:-100px;width:380px;height:380px;background:radial-gradient(circle,rgba(63,185,80,.12) 0%,transparent 70%);pointer-events:none}

.card{
  width:100%;
  max-width:400px;
  margin:20px;
  background:rgba(22,27,34,.85);
  border:1px solid rgba(255,255,255,.1);
  border-radius:20px;
  padding:40px 36px;
  backdrop-filter:blur(20px);
  box-shadow:0 24px 64px rgba(0,0,0,.55),0 0 0 1px rgba(88,166,255,.08);
  animation:fadeUp .4s cubic-bezier(.4,0,.2,1) both;
}
@keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}

.header{text-align:center;margin-bottom:32px}
.logo-wrap{display:inline-flex;align-items:center;justify-content:center;margin-bottom:16px}
.logo-img{width:52px;height:52px;object-fit:contain;border-radius:12px;filter:drop-shadow(0 0 18px rgba(88,166,255,.4))}
.logo-box{width:52px;height:52px;background:linear-gradient(135deg,#1f6feb,#388bfd);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:26px;box-shadow:0 0 22px rgba(88,166,255,.35)}
.title{font-size:1.6em;font-weight:800;color:#e6edf3;letter-spacing:-.5px;margin-bottom:4px}
.subtitle{font-size:.82em;color:#8b949e;font-weight:500}

.form-group{margin-bottom:16px}
label{display:block;font-size:.75em;font-weight:600;color:#8b949e;letter-spacing:.5px;text-transform:uppercase;margin-bottom:6px}
input{
  width:100%;
  background:rgba(13,17,23,.8);
  border:1px solid rgba(255,255,255,.1);
  border-radius:10px;
  padding:11px 14px;
  color:#e6edf3;
  font-size:.9em;
  font-family:inherit;
  outline:none;
  transition:border-color .2s,box-shadow .2s;
}
input:focus{border-color:rgba(88,166,255,.5);box-shadow:0 0 0 3px rgba(88,166,255,.12)}
input::placeholder{color:#484f58}

.btn-login{
  width:100%;
  margin-top:8px;
  padding:12px;
  background:linear-gradient(135deg,#1f6feb,#388bfd);
  border:none;
  border-radius:10px;
  color:#fff;
  font-size:.93em;
  font-weight:700;
  font-family:inherit;
  cursor:pointer;
  letter-spacing:.3px;
  transition:opacity .2s,transform .15s,box-shadow .2s;
  box-shadow:0 4px 14px rgba(31,111,235,.35);
}
.btn-login:hover{opacity:.92;transform:translateY(-1px);box-shadow:0 6px 18px rgba(31,111,235,.45)}
.btn-login:active{transform:translateY(0);opacity:1}

.error-msg{
  display:flex;align-items:center;gap:8px;
  background:rgba(244,112,103,.1);
  border:1px solid rgba(244,112,103,.3);
  border-radius:8px;
  padding:10px 13px;
  font-size:.82em;
  color:#f47067;
  margin-bottom:14px;
  animation:shake .35s cubic-bezier(.36,.07,.19,.97);
}
@keyframes shake{10%,90%{transform:translateX(-2px)}20%,80%{transform:translateX(3px)}30%,50%,70%{transform:translateX(-3px)}40%,60%{transform:translateX(3px)}}

.divider{display:flex;align-items:center;gap:10px;margin:22px 0 16px;color:#484f58;font-size:.72em}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:rgba(255,255,255,.07)}

.demo-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:7px}
.demo-btn{
  background:rgba(255,255,255,.04);
  border:1px solid rgba(255,255,255,.08);
  border-radius:8px;
  padding:8px 6px;
  text-align:center;
  cursor:pointer;
  transition:background .15s,border-color .15s,transform .12s;
  font-family:inherit;
  color:#8b949e;
}
.demo-btn:hover{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.15);transform:translateY(-1px)}
.demo-icon{font-size:1.1em;margin-bottom:3px}
.demo-label{font-size:.65em;font-weight:600;color:#58a6ff;display:block;letter-spacing:.3px}
.demo-creds{font-size:.6em;color:#484f58;display:block;margin-top:2px;font-family:'Courier New',monospace}

.footer{text-align:center;margin-top:22px;font-size:.7em;color:#484f58}
.badge-pill{display:inline-flex;align-items:center;gap:5px;background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.2);border-radius:100px;padding:3px 10px;font-size:.75em;color:#3fb950;font-weight:600}
.dot{width:5px;height:5px;border-radius:50%;background:#3fb950;box-shadow:0 0 5px #3fb950;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
</style>
</head>
<body>
<div class="glow-tl"></div>
<div class="glow-br"></div>
<div class="card">
  <div class="header">
    <div class="logo-wrap">${logo}</div>
    <div class="title">Sentinel</div>
    <div class="subtitle">Sign in to your Security Dashboard</div>
  </div>

  ${errorBlock}

  <form id="loginForm" onsubmit="doLogin(event)">
    <div class="form-group">
      <label for="usernameInput">Username</label>
      <input id="usernameInput" type="text" placeholder="Enter your username" autocomplete="username" autofocus>
    </div>
    <div class="form-group">
      <label for="passwordInput">Password</label>
      <input id="passwordInput" type="password" placeholder="Enter your password" autocomplete="current-password">
    </div>
    <button id="loginBtn" class="btn-login" type="submit">Sign In →</button>
  </form>

  <div class="divider">Quick Demo Login</div>
  <div class="demo-grid">
    <button class="demo-btn" onclick="fill('dev01','dev123')" title="Login as Developer">
      <div class="demo-icon">🧑‍💻</div>
      <span class="demo-label">Developer</span>
      <span class="demo-creds">dev01 / dev123</span>
    </button>
    <button class="demo-btn" onclick="fill('supervisor01','sup123')" title="Login as Supervisor">
      <div class="demo-icon">👁️</div>
      <span class="demo-label">Supervisor</span>
      <span class="demo-creds">supervisor01 / sup123</span>
    </button>
    <button class="demo-btn" onclick="fill('admin','admin123')" title="Login as Administrator">
      <div class="demo-icon">🔐</div>
      <span class="demo-label">Admin</span>
      <span class="demo-creds">admin / admin123</span>
    </button>
  </div>

  <div class="footer">
    <span class="badge-pill"><span class="dot"></span> Sentinel Research System</span>
  </div>
</div>
<script>
const vscode = acquireVsCodeApi();

function fill(u, p) {
  document.getElementById('usernameInput').value = u;
  document.getElementById('passwordInput').value = p;
  document.getElementById('usernameInput').focus();
}

function doLogin(e) {
  e.preventDefault();
  const username = document.getElementById('usernameInput').value.trim();
  const password = document.getElementById('passwordInput').value;
  if (!username || !password) { return; }
  const btn = document.getElementById('loginBtn');
  btn.textContent = 'Signing in…';
  btn.disabled = true;
  vscode.postMessage({ command: 'LOGIN', username, password });
}
</script>
</body>
</html>`;
}

function escHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ─── Logout Button Snippet ─────────────────────────────────────────────────────

/**
 * Returns a small HTML snippet with a header bar containing user info + logout.
 * Inject this at the top of each role dashboard.
 */
export function buildHeaderBar(session: AuthSession, cspSource: string = ''): string {
  const roleColor = session.role === 'administrator' ? '#f47067'
    : session.role === 'supervisor' ? '#d29922'
    : '#58a6ff';
  const roleLabel = session.role === 'administrator' ? '🔐 Administrator'
    : session.role === 'supervisor' ? '👁️ Supervisor'
    : '🧑‍💻 Developer';
  return `
  <div class="auth-bar">
    <div class="auth-user">
      <span class="auth-avatar">${session.displayName.charAt(0).toUpperCase()}</span>
      <div>
        <div class="auth-name">${escHtml(session.displayName)}</div>
        <div class="auth-role" style="color:${roleColor}">${roleLabel}</div>
      </div>
    </div>
    <button class="btn-logout" onclick="doLogout()">Sign Out</button>
  </div>
  <style>
  .auth-bar{display:flex;align-items:center;justify-content:space-between;padding:10px 22px;background:#161b22;border-bottom:1px solid rgba(255,255,255,.08);flex-wrap:wrap;gap:8px}
  .auth-user{display:flex;align-items:center;gap:10px}
  .auth-avatar{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#1f6feb,#388bfd);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.9em;color:#fff;flex-shrink:0;line-height:32px;text-align:center}
  .auth-name{font-size:.82em;font-weight:600;color:#e6edf3}
  .auth-role{font-size:.7em;font-weight:600;margin-top:1px}
  .btn-logout{background:rgba(244,112,103,.1);border:1px solid rgba(244,112,103,.25);border-radius:7px;padding:5px 12px;font-size:.75em;font-weight:600;color:#f47067;cursor:pointer;font-family:inherit;transition:background .15s,transform .12s}
  .btn-logout:hover{background:rgba(244,112,103,.2);transform:translateY(-1px)}
  </style>
  <script>
  const vscode = acquireVsCodeApi();
  function doLogout(){ vscode.postMessage({ command: 'LOGOUT' }); }
  </script>`;
}
