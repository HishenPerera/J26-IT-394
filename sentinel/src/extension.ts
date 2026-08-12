/**
 * Sentinel — VS Code Extension Entry Point
 *
 * This file wires together all components:
 *   SecurityAnalyzer → DiagnosticManager → SecurityEventClient
 *
 * Lifecycle:
 *   activate() → registers all listeners and commands
 *   deactivate() → cleanup
 */

import * as vscode from 'vscode';
import { SecurityAnalyzer } from './analyzer/securityAnalyzer.js';
import { DiagnosticManager, SentinelHoverProvider } from './diagnostics/diagnosticManager.js';
import { SecurityEventClient } from './events/securityEventClient.js';
import { DeveloperAction, SecurityFinding } from './analyzer/types.js';
import { VULNERABILITY_METADATA } from './diagnostics/vulnerabilityMetadata.js';
import { generateContextualExplanation } from './diagnostics/contextualExplainer.js';

// ─── Module-level instances (kept alive for the extension lifetime) ─────────

let analyzer: SecurityAnalyzer;
let diagnosticManager: DiagnosticManager;
let eventClient: SecurityEventClient;
let outputChannel: vscode.OutputChannel;
let debounceTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

// Per-file finding cache (used by code actions)
let findingsCache: Map<string, SecurityFinding[]> = new Map();

// Live dashboard panel — kept open and refreshed on every analysis
let dashboardPanel: vscode.WebviewPanel | undefined;

// Extension root URI — stored in activate() for resource loading
let extensionUri: vscode.Uri;

// ─── activate() ──────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  extensionUri = context.extensionUri; // store for webview resource loading
  outputChannel = vscode.window.createOutputChannel('Sentinel Security');
  log('🛡 Sentinel activated.');

  analyzer = new SecurityAnalyzer();
  diagnosticManager = new DiagnosticManager();
  eventClient = new SecurityEventClient();

  // ── Register commands ────────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.commands.registerCommand('sentinel.showOutput', () => {
      outputChannel.show();
    }),

    vscode.commands.registerCommand('sentinel.analyzeDocument', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        analyzeDocument(editor.document, true);
      } else {
        vscode.window.showInformationMessage('Sentinel: No active document to analyze.');
      }
    }),

    vscode.commands.registerCommand('sentinel.showDashboard', () => {
      showDashboard(context);
    }),

    vscode.commands.registerCommand('sentinel.explainFinding',
      (args: { findingId: string }) => {
        handleExplainAction(args.findingId);
      }
    ),

    vscode.commands.registerCommand('sentinel.applyFix',
      (args: { findingId: string }) => {
        handleFixAction(args.findingId);
      }
    ),

    vscode.commands.registerCommand('sentinel.ignoreFinding',
      (args: { findingId: string }) => {
        handleIgnoreAction(args.findingId);
      }
    ),
  );

  // ── Register hover provider ──────────────────────────────────────────────

  const hoverProvider = new SentinelHoverProvider(diagnosticManager);
  context.subscriptions.push(
    vscode.languages.registerHoverProvider({ scheme: 'file' }, hoverProvider)
  );

  // ── Register code action provider ───────────────────────────────────────

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      new SentinelCodeActionProvider(),
    )
  );

  // ── Document event listeners ─────────────────────────────────────────────

  // Analyze when a file is opened
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(doc => {
      if (doc.uri.scheme === 'file') {
        analyzeDocument(doc, false);
      }
    })
  );

  // Analyze with debounce when code changes (Phase 9 in guide)
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      if (event.document.uri.scheme !== 'file') {
        return;
      }

      const config = vscode.workspace.getConfiguration('sentinel');
      if (!config.get<boolean>('enabled', true)) {
        return;
      }

      const key = event.document.uri.toString();
      const delay = config.get<number>('debounceMs', 400);

      // Clear previous timer for this document
      const existing = debounceTimers.get(key);
      if (existing !== undefined) {
        clearTimeout(existing);
      }

      // Schedule analysis after debounce delay
      const timer = setTimeout(() => {
        debounceTimers.delete(key);
        analyzeDocument(event.document, false);
      }, delay);

      debounceTimers.set(key, timer);
    })
  );

  // Clear diagnostics when a file is closed
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument(doc => {
      diagnosticManager.clearDiagnostics(doc);
      findingsCache.delete(doc.uri.toString());
    })
  );

  // On file save: immediate analysis (no debounce) + instant dashboard refresh
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      if (doc.uri.scheme !== 'file') {
        return;
      }
      // Cancel any pending debounce for this file — we'll run immediately
      const key = doc.uri.toString();
      const existing = debounceTimers.get(key);
      if (existing !== undefined) {
        clearTimeout(existing);
        debounceTimers.delete(key);
      }
      analyzeDocument(doc, false);
    })
  );

  // Analyze files already open when extension activates
  vscode.workspace.textDocuments.forEach(doc => {
    if (doc.uri.scheme === 'file') {
      analyzeDocument(doc, false);
    }
  });

  // Status bar item
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.text = '$(shield) Sentinel';
  statusBar.tooltip = 'Sentinel Security — Click to show dashboard';
  statusBar.command = 'sentinel.showDashboard';
  statusBar.show();
  context.subscriptions.push(statusBar);

  log(`Session: ${eventClient.getSessionId()}`);
  log(`Rules loaded: ${analyzer.getRules().map(r => r.ruleName).join(', ')}`);
}

// ─── deactivate() ─────────────────────────────────────────────────────────────

export function deactivate(): void {
  diagnosticManager.dispose();
  eventClient.dispose();
  outputChannel.dispose();
  // Clear all pending debounce timers
  debounceTimers.forEach(t => clearTimeout(t));
  debounceTimers.clear();
}

// ─── Core Analysis Flow ───────────────────────────────────────────────────────

async function analyzeDocument(
  document: vscode.TextDocument,
  forceNotify: boolean,
): Promise<void> {
  const config = vscode.workspace.getConfiguration('sentinel');
  if (!config.get<boolean>('enabled', true)) {
    return;
  }

  const text = document.getText();
  const fileName = document.uri.fsPath;
  const languageId = document.languageId;

  const findings = analyzer.analyze(text, fileName, languageId);
  const summary = analyzer.summarize(findings);

  // Update Problems panel
  diagnosticManager.updateDiagnostics(document, findings);

  // Cache findings for code actions
  findingsCache.set(document.uri.toString(), findings);

  // Log to output channel
  if (findings.length > 0 || forceNotify) {
    logFindings(document, findings);
  }

  // Report to backend (Phase 5)
  for (const finding of findings) {
    void eventClient.reportDetection(finding);
  }

  // Show terminal alert for HIGH/CRITICAL findings
  if (findings.some(f => f.severity === 'HIGH' || f.severity === 'CRITICAL')) {
    logSecurityAlert(findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL'));
  }

  // Push updated data to the live dashboard (if it's open)
  refreshDashboard();
}

// ─── Developer Action Handlers ────────────────────────────────────────────────

function handleExplainAction(findingId: string): void {
  const finding = findFindingById(findingId);
  if (!finding) {
    return;
  }

  const meta = VULNERABILITY_METADATA[finding.type];
  const panel = vscode.window.createWebviewPanel(
    'sentinel.explain',
    `Sentinel: ${finding.type}`,
    vscode.ViewColumn.Beside,
    { enableScripts: false },
  );

  panel.webview.html = buildExplainHtml(finding, meta);
  void eventClient.reportAction(finding, DeveloperAction.EXPLANATION_VIEWED);
  log(`[Action] EXPLANATION_VIEWED — ${finding.type} at line ${finding.lineNumber}`);
}

function handleFixAction(findingId: string): void {
  const finding = findFindingById(findingId);
  if (!finding) {
    return;
  }

  const meta = VULNERABILITY_METADATA[finding.type];
  if (meta?.secureExample) {
    const panel = vscode.window.createWebviewPanel(
      'sentinel.fix',
      `Sentinel Fix: ${finding.type}`,
      vscode.ViewColumn.Beside,
      { enableScripts: false },
    );
    panel.webview.html = buildFixHtml(finding, meta);
  }

  void eventClient.reportAction(finding, DeveloperAction.SECURE_EXAMPLE_VIEWED);
  log(`[Action] SECURE_EXAMPLE_VIEWED — ${finding.type} at line ${finding.lineNumber}`);
}

function handleIgnoreAction(findingId: string): void {
  const finding = findFindingById(findingId);
  if (!finding) {
    return;
  }

  vscode.window.showInformationMessage(
    `Sentinel: Ignored ${finding.type} at line ${finding.lineNumber}. ` +
    `This finding will reappear if the code is not fixed.`
  );

  void eventClient.reportAction(finding, DeveloperAction.IGNORED);
  log(`[Action] IGNORED — ${finding.type} at line ${finding.lineNumber}`);
}

function findFindingById(findingId: string): SecurityFinding | undefined {
  for (const findings of findingsCache.values()) {
    const found = findings.find(f => f.id === findingId);
    if (found) {
      return found;
    }
  }
  return undefined;
}

// ─── Code Actions Provider ────────────────────────────────────────────────────

class SentinelCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
  ): vscode.CodeAction[] {
    const findings = findingsCache.get(document.uri.toString()) ?? [];
    const actions: vscode.CodeAction[] = [];

    for (const finding of findings) {
      const findingLine = finding.lineNumber - 1;
      if (!range.contains(new vscode.Position(findingLine, 0))) {
        continue;
      }

      const explainAction = new vscode.CodeAction(
        `$(book) Sentinel: Explain ${finding.type}`,
        vscode.CodeActionKind.QuickFix,
      );
      explainAction.command = {
        command: 'sentinel.explainFinding',
        title: 'Explain',
        arguments: [{ findingId: finding.id }],
      };

      const fixAction = new vscode.CodeAction(
        `$(wrench) Sentinel: Show Secure Fix for ${finding.type}`,
        vscode.CodeActionKind.QuickFix,
      );
      fixAction.command = {
        command: 'sentinel.applyFix',
        title: 'Show Fix',
        arguments: [{ findingId: finding.id }],
      };

      const ignoreAction = new vscode.CodeAction(
        `$(eye-closed) Sentinel: Ignore this ${finding.type} warning`,
        vscode.CodeActionKind.QuickFix,
      );
      ignoreAction.command = {
        command: 'sentinel.ignoreFinding',
        title: 'Ignore',
        arguments: [{ findingId: finding.id }],
      };

      actions.push(explainAction, fixAction, ignoreAction);
    }

    return actions;
  }
}

// ─── Dashboard Webview ────────────────────────────────────────────────────────

/** Refresh the live dashboard panel with current findings from the cache. */
function refreshDashboard(): void {
  if (!dashboardPanel) {
    return;
  }
  const allFindings: SecurityFinding[] = [];
  for (const findings of findingsCache.values()) {
    allFindings.push(...findings);
  }
  const summary = analyzer.summarize(allFindings);

  // Convert the local logo path to a webview-safe URI
  const logoUri = dashboardPanel.webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, 'resources', 'sentinel-logo.png')
  );

  // Append a cache-buster query parameter to force webview to reload the image
  const logoUriWithCacheBuster = logoUri.toString() + '?t=' + Date.now();

  dashboardPanel.webview.html = buildDashboardHtml(summary, allFindings, logoUriWithCacheBuster);
}

function showDashboard(context: vscode.ExtensionContext): void {
  // If already open, just bring it to front and refresh
  if (dashboardPanel) {
    dashboardPanel.reveal(vscode.ViewColumn.Beside);
    refreshDashboard();
    return;
  }

  dashboardPanel = vscode.window.createWebviewPanel(
    'sentinel.dashboard',
    'Sentinel Security Dashboard',
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      // Allow the webview to load images from the resources/ folder
      localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'resources')],
    },
  );

  // Clear the reference when the user closes the panel
  dashboardPanel.onDidDispose(() => {
    dashboardPanel = undefined;
  }, null, context.subscriptions);

  refreshDashboard();
}

// ─── Logging ──────────────────────────────────────────────────────────────────

function log(message: string): void {
  const timestamp = new Date().toLocaleTimeString();
  outputChannel.appendLine(`[${timestamp}] ${message}`);
}

function logFindings(document: vscode.TextDocument, findings: SecurityFinding[]): void {
  const name = document.fileName.split('/').pop() ?? document.fileName;
  if (findings.length === 0) {
    log(`✅ ${name} — No issues found`);
    return;
  }

  log(`\n${'─'.repeat(50)}`);
  log(`📄 ${name} — ${findings.length} issue(s) found`);
  for (const f of findings) {
    const conf = Math.round(f.confidence * 100);
    log(`  ${severityIcon(f.severity)} [${f.severity}] ${f.type} — Line ${f.lineNumber} (${conf}% confidence)`);
    log(`     ${f.codeSnippet.substring(0, 80)}${f.codeSnippet.length > 80 ? '...' : ''}`);
  }
  log('─'.repeat(50));
}

function logSecurityAlert(findings: SecurityFinding[]): void {
  outputChannel.appendLine('');
  outputChannel.appendLine('━'.repeat(44));
  outputChannel.appendLine('  🛡 SENTINEL SECURITY ALERT');
  outputChannel.appendLine('━'.repeat(44));
  for (const f of findings) {
    outputChannel.appendLine('');
    outputChannel.appendLine(`  ${f.type}`);
    outputChannel.appendLine(`  File:     ${f.fileName.split('/').pop()}`);
    outputChannel.appendLine(`  Line:     ${f.lineNumber}`);
    outputChannel.appendLine(`  Severity: ${f.severity}`);
    outputChannel.appendLine(`  Confidence: ${Math.round(f.confidence * 100)}%`);
    outputChannel.appendLine('');
    outputChannel.appendLine('  Actions: [Explain] [Fix] [Ignore]');
    outputChannel.appendLine('  (Use the lightbulb 💡 or hover over the red underline)');
    outputChannel.appendLine('');
    outputChannel.appendLine('─'.repeat(44));
  }
  outputChannel.appendLine('');
}

function severityIcon(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return '🚨';
    case 'HIGH':     return '🔴';
    case 'MEDIUM':   return '🟠';
    case 'LOW':      return '🟡';
    default:         return 'ℹ️';
  }
}

// ─── HTML Builders ────────────────────────────────────────────────────────────

function buildExplainHtml(finding: SecurityFinding, _meta: any): string {
  const ctx = generateContextualExplanation(finding);
  const conf = Math.round(finding.confidence * 100);
  const sevColor = finding.severity === 'CRITICAL' || finding.severity === 'HIGH' ? '#f14c4c' :
                   finding.severity === 'MEDIUM' ? '#e9a825' : '#73c991';
  const meta = VULNERABILITY_METADATA[finding.type];
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', var(--vscode-font-family), sans-serif; padding: 24px; color: var(--vscode-editor-foreground); background: var(--vscode-editor-background); line-height: 1.6; }
    .header { display: flex; align-items: flex-start; gap: 16px; margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid var(--vscode-panel-border); }
    .severity-dot { width: 14px; height: 14px; border-radius: 50%; background: ${sevColor}; margin-top: 6px; flex-shrink: 0; box-shadow: 0 0 8px ${sevColor}; }
    .title { font-size: 1.3em; font-weight: 700; color: var(--vscode-editor-foreground); }
    .subtitle { font-size: 0.9em; color: var(--vscode-descriptionForeground); margin-top: 4px; }
    .badges { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
    .badge { display: inline-flex; align-items: center; gap: 5px; padding: 3px 10px; border-radius: 100px; font-size: 11px; font-weight: 600; letter-spacing: 0.5px; }
    .badge-sev { background: ${sevColor}22; color: ${sevColor}; border: 1px solid ${sevColor}44; }
    .badge-conf { background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); }
    .badge-rule { background: var(--vscode-editor-inactiveSelectionBackground); color: var(--vscode-descriptionForeground); }
    .section { margin: 20px 0; }
    .section-label { font-size: 11px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: var(--vscode-descriptionForeground); margin-bottom: 10px; }
    .section-body { font-size: 0.93em; color: var(--vscode-editor-foreground); }
    .code-block { position: relative; border-radius: 8px; overflow: hidden; margin: 10px 0; }
    .code-label { font-size: 10px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; padding: 6px 14px; }
    .code-label.danger { background: #f14c4c22; color: #f14c4c; border-bottom: 1px solid #f14c4c33; }
    .code-label.safe { background: #73c99122; color: #73c991; border-bottom: 1px solid #73c99133; }
    pre { font-family: 'Fira Code', 'Courier New', monospace; font-size: 13px; padding: 14px 16px; background: var(--vscode-textCodeBlock-background); overflow-x: auto; margin: 0; white-space: pre-wrap; word-break: break-word; }
    .pre-danger { border: 1px solid #f14c4c33; border-radius: 8px; overflow: hidden; }
    .pre-safe   { border: 1px solid #73c99133; border-radius: 8px; overflow: hidden; }
    .attack-box { background: #e9a82511; border: 1px solid #e9a82533; border-radius: 8px; padding: 14px 16px; font-size: 0.9em; white-space: pre-wrap; font-family: 'Fira Code', monospace; }
    .fix-note { background: #73c99111; border: 1px solid #73c99133; border-radius: 8px; padding: 12px 16px; font-size: 0.9em; margin-top: 10px; }
    .divider { border: none; border-top: 1px solid var(--vscode-panel-border); margin: 24px 0; }
    code { font-family: 'Fira Code', monospace; background: var(--vscode-textCodeBlock-background); padding: 1px 6px; border-radius: 3px; font-size: 0.92em; }
    a { color: var(--vscode-textLink-foreground); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .ref-list { list-style: none; margin-top: 8px; display: flex; flex-direction: column; gap: 4px; }
    .ref-list a { font-size: 0.85em; }
  </style>
</head>
<body>
  <div class="header">
    <div class="severity-dot"></div>
    <div>
      <div class="title">${finding.type.replace(/_/g, ' ')}</div>
      <div class="subtitle">${ctx.headline}</div>
      <div class="badges">
        <span class="badge badge-sev">${finding.severity}</span>
        <span class="badge badge-conf">${conf}% confidence</span>
        <span class="badge badge-rule">${finding.detectedByRule} &mdash; Line ${finding.lineNumber}</span>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-label">Why is your code vulnerable?</div>
    <div class="section-body">${ctx.whyDangerous}</div>
  </div>

  <div class="section">
    <div class="section-label">Your vulnerable code</div>
    <div class="pre-danger">
      <div class="code-label danger">❌ Detected in your file &mdash; Line ${finding.lineNumber}</div>
      <pre>${escHtml(ctx.vulnerableCode)}</pre>
    </div>
  </div>

  <div class="section">
    <div class="section-label">Attack scenario</div>
    <div class="attack-box">${escHtml(ctx.attackScenario)}</div>
  </div>

  <hr class="divider">

  <div class="section">
    <div class="section-label">Fixed version of your code</div>
    <div class="pre-safe">
      <div class="code-label safe">✅ Secure replacement</div>
      <pre>${escHtml(ctx.fixedCode)}</pre>
    </div>
    <div class="fix-note">💡 ${escHtml(ctx.fixExplanation)}</div>
  </div>

  ${meta?.references?.length ? `
  <div class="section">
    <div class="section-label">References</div>
    <ul class="ref-list">
      ${meta.references.map((r: string) => `<li><a href="${r}" target="_blank">${r}</a></li>`).join('')}
    </ul>
  </div>` : ''}
</body>
</html>`;
}

function buildFixHtml(finding: SecurityFinding, _meta: any): string {
  const ctx = generateContextualExplanation(finding);
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=Fira+Code&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', sans-serif; padding: 24px; color: var(--vscode-editor-foreground); background: var(--vscode-editor-background); line-height: 1.6; }
    h1 { font-size: 1.2em; color: #73c991; margin-bottom: 6px; }
    .subtitle { color: var(--vscode-descriptionForeground); font-size: 0.9em; margin-bottom: 24px; }
    .code-block { border-radius: 8px; overflow: hidden; margin: 12px 0; }
    .code-label { font-size: 10px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; padding: 6px 14px; }
    .code-label.danger { background: #f14c4c22; color: #f14c4c; }
    .code-label.safe   { background: #73c99122; color: #73c991; }
    pre { font-family: 'Fira Code', monospace; font-size: 13px; padding: 14px 16px; background: var(--vscode-textCodeBlock-background); overflow-x: auto; margin: 0; white-space: pre-wrap; word-break: break-word; }
    .pre-danger { border: 1px solid #f14c4c33; border-radius: 8px; overflow: hidden; }
    .pre-safe   { border: 1px solid #73c99133; border-radius: 8px; overflow: hidden; }
    .note { background: #73c99111; border: 1px solid #73c99133; border-radius: 8px; padding: 12px 16px; font-size: 0.9em; margin-top: 12px; }
  </style>
</head>
<body>
  <h1>✅ Secure Fix &mdash; ${finding.type.replace(/_/g, ' ')}</h1>
  <div class="subtitle">Line ${finding.lineNumber} in ${finding.fileName.split('/').pop()}</div>

  <div class="pre-danger">
    <div class="code-label danger">❌ Your vulnerable code</div>
    <pre>${escHtml(ctx.vulnerableCode)}</pre>
  </div>

  <div class="pre-safe" style="margin-top:16px">
    <div class="code-label safe">✅ Fixed version</div>
    <pre>${escHtml(ctx.fixedCode)}</pre>
  </div>

  <div class="note">💡 ${escHtml(ctx.fixExplanation)}</div>
</body>
</html>`;
}

function buildDashboardHtml(summary: any, findings: SecurityFinding[], logoUri: string = ''): string {
  const scoreRaw = findings.length === 0 ? 100 :
    Math.max(0, 100 - (summary.criticalCount * 25 + summary.highCount * 10 + summary.mediumCount * 5 + summary.lowCount * 2));
  const scoreColor = scoreRaw >= 80 ? '#73c991' : scoreRaw >= 50 ? '#e9a825' : '#f14c4c';

  // Build a detailed card for each finding using contextual explanation
  const findingCards = findings.map(f => {
    const ctx = generateContextualExplanation(f);
    const conf = Math.round(f.confidence * 100);
    const sevColor = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? '#f14c4c' :
                     f.severity === 'MEDIUM' ? '#e9a825' : '#73c991';
    const sevIcon  = f.severity === 'CRITICAL' ? '🚨' :
                     f.severity === 'HIGH' ? '🔴' :
                     f.severity === 'MEDIUM' ? '🟠' : '🟡';
    return `
    <div class="finding-card" id="card-${f.id}">
      <!-- Card header -->
      <div class="card-header" onclick="toggleCard('${f.id}')">
        <div class="card-header-left">
          <span class="sev-pill" style="background:${sevColor}22;color:${sevColor};border-color:${sevColor}44">
            ${sevIcon} ${f.severity}
          </span>
          <div class="card-title">${f.type.replace(/_/g, ' ')}</div>
          <div class="card-sub">${f.fileName.split('/').pop()} &mdash; Line ${f.lineNumber}</div>
        </div>
        <div class="card-header-right">
          <span class="conf-badge">${conf}% confidence</span>
          <span class="toggle-icon" id="icon-${f.id}">&#9660;</span>
        </div>
      </div>

      <!-- Headline (always visible) -->
      <div class="card-headline">${escHtml(ctx.headline)}</div>

      <!-- Expandable detail -->
      <div class="card-detail" id="detail-${f.id}">

        <!-- Why dangerous -->
        <div class="detail-section">
          <div class="detail-label">Why is this vulnerable?</div>
          <div class="detail-text">${escHtml(ctx.whyDangerous)}</div>
        </div>

        <!-- Side-by-side: vulnerable vs fixed -->
        <div class="code-compare">
          <div class="code-col">
            <div class="code-label danger-label">❌ Your vulnerable code</div>
            <pre class="pre-danger">${escHtml(ctx.vulnerableCode)}</pre>
          </div>
          <div class="code-col">
            <div class="code-label safe-label">✅ Fixed version</div>
            <pre class="pre-safe">${escHtml(ctx.fixedCode)}</pre>
          </div>
        </div>

        <!-- Attack scenario -->
        <div class="detail-section">
          <div class="detail-label">Attack scenario</div>
          <div class="attack-box">${escHtml(ctx.attackScenario)}</div>
        </div>

        <!-- Fix explanation -->
        <div class="fix-note">💡 ${escHtml(ctx.fixExplanation)}</div>

      </div>
    </div>`;
  }).join('');

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', var(--vscode-font-family), sans-serif; padding: 24px; color: var(--vscode-editor-foreground); background: var(--vscode-editor-background); line-height: 1.6; }

    /* ── Header ── */
    .dash-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 28px; padding-bottom: 16px; border-bottom: 1px solid var(--vscode-panel-border); }
    .dash-title { display: flex; align-items: center; gap: 14px; }
    .dash-logo { width: 44px; height: 44px; object-fit: contain; flex-shrink: 0; }
    .dash-title-text { display: flex; flex-direction: column; gap: 1px; }
    .dash-title-main { font-size: 1.4em; font-weight: 700; letter-spacing: -0.3px; }
    .dash-title-sub { font-size: 0.75em; color: var(--vscode-descriptionForeground); text-transform: uppercase; letter-spacing: 1px; }
    .dash-session { font-size: 0.78em; color: var(--vscode-descriptionForeground); }

    /* ── Stat Cards ── */
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin-bottom: 32px; }
    .stat { padding: 16px 18px; border-radius: 10px; background: var(--vscode-editor-inactiveSelectionBackground); border: 1px solid var(--vscode-panel-border); }
    .stat-num { font-size: 2.2em; font-weight: 700; line-height: 1; }
    .stat-label { font-size: 0.75em; color: var(--vscode-descriptionForeground); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }

    /* ── Section title ── */
    .section-title { font-size: 0.85em; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: var(--vscode-descriptionForeground); margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
    .section-title::after { content: ''; flex: 1; height: 1px; background: var(--vscode-panel-border); }

    /* ── Finding Cards ── */
    .findings { display: flex; flex-direction: column; gap: 12px; }
    .finding-card { border: 1px solid var(--vscode-panel-border); border-radius: 10px; overflow: hidden; background: var(--vscode-editor-background); transition: box-shadow 0.2s; }
    .finding-card:hover { box-shadow: 0 2px 12px rgba(0,0,0,0.15); }

    /* Card header (always visible, clickable) */
    .card-header { display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; cursor: pointer; user-select: none; background: var(--vscode-editor-inactiveSelectionBackground); }
    .card-header:hover { background: var(--vscode-list-hoverBackground); }
    .card-header-left { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
    .card-header-right { display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
    .sev-pill { padding: 3px 10px; border-radius: 100px; font-size: 11px; font-weight: 700; border: 1px solid; white-space: nowrap; }
    .card-title { font-weight: 600; font-size: 0.95em; }
    .card-sub { font-size: 0.8em; color: var(--vscode-descriptionForeground); }
    .conf-badge { font-size: 11px; color: var(--vscode-descriptionForeground); }
    .toggle-icon { font-size: 12px; color: var(--vscode-descriptionForeground); transition: transform 0.2s; display: inline-block; }
    .toggle-icon.open { transform: rotate(180deg); }

    /* Headline (always visible below header) */
    .card-headline { padding: 10px 18px 12px; font-size: 0.88em; color: var(--vscode-descriptionForeground); border-bottom: 1px solid var(--vscode-panel-border); background: var(--vscode-editor-background); }

    /* Expandable detail */
    .card-detail { display: none; padding: 18px; }
    .card-detail.open { display: block; }

    .detail-section { margin-bottom: 18px; }
    .detail-label { font-size: 10px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: var(--vscode-descriptionForeground); margin-bottom: 8px; }
    .detail-text { font-size: 0.9em; }

    /* Side-by-side code comparison */
    .code-compare { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 18px; }
    @media (max-width: 700px) { .code-compare { grid-template-columns: 1fr; } }
    .code-col {}
    .code-label { font-size: 10px; font-weight: 700; letter-spacing: 0.8px; text-transform: uppercase; padding: 6px 12px; }
    .danger-label { background: #f14c4c1a; color: #f14c4c; border-radius: 6px 6px 0 0; }
    .safe-label   { background: #73c9911a; color: #73c991; border-radius: 6px 6px 0 0; }
    pre { font-family: 'Fira Code', 'Courier New', monospace; font-size: 12px; padding: 12px 14px; background: var(--vscode-textCodeBlock-background); overflow-x: auto; margin: 0; white-space: pre-wrap; word-break: break-word; }
    .pre-danger { border: 1px solid #f14c4c33; border-radius: 0 0 6px 6px; }
    .pre-safe   { border: 1px solid #73c99133; border-radius: 0 0 6px 6px; }

    /* Attack box */
    .attack-box { background: #e9a82511; border: 1px solid #e9a82533; border-radius: 8px; padding: 12px 14px; font-size: 0.85em; white-space: pre-wrap; font-family: 'Fira Code', monospace; }

    /* Fix note */
    .fix-note { background: #73c99111; border: 1px solid #73c99133; border-radius: 8px; padding: 11px 14px; font-size: 0.88em; margin-top: 8px; }

    .empty-state { text-align: center; padding: 48px; color: #73c991; }
    .empty-state .check { font-size: 3em; margin-bottom: 12px; }
  </style>
</head>
<body>
  <div class="dash-header">
    <div class="dash-title">
      ${logoUri
        ? `<img src="${logoUri}" alt="Sentinel" class="dash-logo">`
        : ''}
      <div class="dash-title-text">
        <div class="dash-title-main">Sentinel</div>
        <div class="dash-title-sub">Security Dashboard</div>
      </div>
    </div>
    <div class="dash-session">Session: ${eventClient?.getSessionId() ?? 'N/A'}</div>
  </div>

  <!-- Stat cards -->
  <div class="stats">
    <div class="stat">
      <div class="stat-num" style="color:${scoreColor}">${scoreRaw}%</div>
      <div class="stat-label">Security Score</div>
    </div>
    <div class="stat">
      <div class="stat-num" style="color:#f14c4c">${summary.criticalCount}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat">
      <div class="stat-num" style="color:#f17c4c">${summary.highCount}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat">
      <div class="stat-num" style="color:#e9a825">${summary.mediumCount}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat">
      <div class="stat-num">${summary.totalFindings}</div>
      <div class="stat-label">Total Issues</div>
    </div>
    <div class="stat">
      <div class="stat-num">${analyzer?.getRules().length ?? 0}</div>
      <div class="stat-label">Active Rules</div>
    </div>
  </div>

  <!-- Finding cards with contextual explanation -->
  <div class="section-title">Detected Vulnerabilities</div>

  ${findings.length === 0
    ? `<div class="empty-state"><div class="check">✅</div><div>No issues detected in open files.</div></div>`
    : `<div class="findings">${findingCards}</div>`
  }

  <script>
    function toggleCard(id) {
      const detail = document.getElementById('detail-' + id);
      const icon   = document.getElementById('icon-' + id);
      if (!detail || !icon) return;
      const isOpen = detail.classList.contains('open');
      detail.classList.toggle('open', !isOpen);
      icon.classList.toggle('open', !isOpen);
    }
    // Auto-expand the first card
    const firstCard = document.querySelector('.card-header');
    if (firstCard) {
      const id = firstCard.parentElement?.id?.replace('card-', '');
      if (id) toggleCard(id);
    }
  <\/script>
</body>
</html>`;
}

function escHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
