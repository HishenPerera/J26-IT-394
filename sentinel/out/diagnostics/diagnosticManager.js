"use strict";
/**
 * Sentinel — Diagnostic Manager
 *
 * Translates SecurityFinding objects into VS Code Diagnostics.
 * Manages the Problems panel, red underlines, and hover explanations.
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
exports.SentinelHoverProvider = exports.DiagnosticManager = void 0;
exports.isDiagnosticWithFinding = isDiagnosticWithFinding;
const vscode = __importStar(require("vscode"));
const types_js_1 = require("../analyzer/types.js");
const vulnerabilityMetadata_js_1 = require("./vulnerabilityMetadata.js");
class DiagnosticManager {
    constructor() {
        this.collection = vscode.languages.createDiagnosticCollection('sentinel');
    }
    /**
     * Update the Problems panel for a given document.
     * Replaces all previous findings for that file.
     */
    updateDiagnostics(document, findings) {
        const diagnostics = findings.map(f => this.findingToDiagnostic(document, f));
        this.collection.set(document.uri, diagnostics);
    }
    /**
     * Clear diagnostics for a specific document.
     */
    clearDiagnostics(document) {
        this.collection.delete(document.uri);
    }
    /**
     * Clear all diagnostics across all files.
     */
    clearAll() {
        this.collection.clear();
    }
    /**
     * Dispose the diagnostic collection (called on extension deactivate).
     */
    dispose() {
        this.collection.dispose();
    }
    // ─── Private ───────────────────────────────────────────────────────────────
    findingToDiagnostic(document, finding) {
        // Convert to 0-indexed line
        const lineIndex = Math.max(0, finding.lineNumber - 1);
        const line = document.lineAt(Math.min(lineIndex, document.lineCount - 1));
        // Highlight the whole line (we'll refine to exact column range in Phase 7)
        const range = finding.rangeStart !== undefined && finding.rangeEnd !== undefined
            ? this.offsetsToRange(document, finding.rangeStart, finding.rangeEnd)
            : line.range;
        const severity = this.mapSeverity(finding.severity);
        // Build the diagnostic message
        const confidencePct = Math.round(finding.confidence * 100);
        const label = `🛡 Sentinel [${finding.type}]`;
        const message = `${label}\n` +
            `${finding.message}\n` +
            `Severity: ${finding.severity} | Confidence: ${confidencePct}%`;
        const diagnostic = new vscode.Diagnostic(range, message, severity);
        // Tag so VS Code categorizes it correctly
        diagnostic.source = 'Sentinel';
        diagnostic.code = {
            value: finding.type,
            target: vscode.Uri.parse(`https://owasp.org/www-community/attacks/${this.owaspSlug(finding.type)}`),
        };
        // Attach finding metadata for code actions to consume
        diagnostic.__sentinelFinding = finding;
        return diagnostic;
    }
    offsetsToRange(document, start, end) {
        try {
            const startPos = document.positionAt(start);
            const endPos = document.positionAt(end);
            return new vscode.Range(startPos, endPos);
        }
        catch {
            return document.lineAt(0).range;
        }
    }
    mapSeverity(severity) {
        switch (severity) {
            case types_js_1.Severity.CRITICAL:
            case types_js_1.Severity.HIGH:
                return vscode.DiagnosticSeverity.Error;
            case types_js_1.Severity.MEDIUM:
                return vscode.DiagnosticSeverity.Warning;
            case types_js_1.Severity.LOW:
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }
    owaspSlug(type) {
        const map = {
            SQL_INJECTION: 'SQL_Injection',
            XSS: 'Cross_Site_Scripting_(XSS)',
            HARDCODED_SECRET: 'Use_of_Hard-coded_Cryptographic_Key',
            COMMAND_INJECTION: 'Command_Injection',
            PATH_TRAVERSAL: 'Path_Traversal',
        };
        return map[type] || type;
    }
}
exports.DiagnosticManager = DiagnosticManager;
function isDiagnosticWithFinding(d) {
    return '__sentinelFinding' in d;
}
// ─── Hover Provider ───────────────────────────────────────────────────────────
/**
 * Provides rich hover explanations when the developer hovers over a red underline.
 */
class SentinelHoverProvider {
    constructor(diagnosticManager) {
        this.diagnosticManager = diagnosticManager;
    }
    provideHover(document, position) {
        // Find any Sentinel diagnostic at this position
        const diags = vscode.languages.getDiagnostics(document.uri);
        for (const diag of diags) {
            if (diag.source !== 'Sentinel') {
                continue;
            }
            if (!diag.range.contains(position)) {
                continue;
            }
            if (!isDiagnosticWithFinding(diag)) {
                continue;
            }
            const finding = diag.__sentinelFinding;
            const meta = vulnerabilityMetadata_js_1.VULNERABILITY_METADATA[finding.type];
            const confidencePct = Math.round(finding.confidence * 100);
            const md = new vscode.MarkdownString(undefined, true);
            md.isTrusted = true;
            // Header
            md.appendMarkdown(`## 🛡 Sentinel — ${this.severityIcon(finding.severity)} ${meta?.title ?? finding.type}\n\n`);
            // Finding details
            md.appendMarkdown(`**Severity:** \`${finding.severity}\` &nbsp;|&nbsp; **Confidence:** \`${confidencePct}%\`\n\n`);
            md.appendMarkdown(`---\n\n`);
            // Explanation
            if (meta) {
                md.appendMarkdown(`**What happened?**\n\n${meta.description}\n\n`);
                md.appendMarkdown(`**Why is this dangerous?**\n\n${meta.impact}\n\n`);
                md.appendMarkdown(`**Recommended fix:**\n\n${meta.recommendation}\n\n`);
                if (meta.secureExample) {
                    md.appendMarkdown(`**Secure example:**\n\`\`\`\n${meta.secureExample}\n\`\`\`\n\n`);
                }
            }
            else {
                md.appendMarkdown(`${finding.message}\n\n`);
            }
            // Action buttons
            const explainCmd = encodeURIComponent(JSON.stringify({ findingId: finding.id }));
            const fixCmd = encodeURIComponent(JSON.stringify({ findingId: finding.id }));
            const ignoreCmd = encodeURIComponent(JSON.stringify({ findingId: finding.id }));
            md.appendMarkdown(`[$(book) Explain](command:sentinel.explainFinding?${explainCmd}) &nbsp;&nbsp;` +
                `[$(wrench) Fix](command:sentinel.applyFix?${fixCmd}) &nbsp;&nbsp;` +
                `[$(eye-closed) Ignore](command:sentinel.ignoreFinding?${ignoreCmd})`);
            return new vscode.Hover(md);
        }
        return undefined;
    }
    severityIcon(severity) {
        switch (severity) {
            case types_js_1.Severity.CRITICAL: return '🚨';
            case types_js_1.Severity.HIGH: return '🔴';
            case types_js_1.Severity.MEDIUM: return '🟠';
            case types_js_1.Severity.LOW: return '🟡';
            default: return 'ℹ️';
        }
    }
}
exports.SentinelHoverProvider = SentinelHoverProvider;
//# sourceMappingURL=diagnosticManager.js.map