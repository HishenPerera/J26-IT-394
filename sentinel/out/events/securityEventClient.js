"use strict";
/**
 * Sentinel — Security Event Client
 *
 * Sends security events and developer action events to Member 2's backend API.
 * Includes offline queueing so events aren't lost if the backend is unavailable.
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
exports.SecurityEventClient = void 0;
const types_js_1 = require("../analyzer/types.js");
const vscode = __importStar(require("vscode"));
class SecurityEventClient {
    constructor() {
        this.queue = [];
        this.sessionId = this.generateSessionId();
    }
    // ─── Public API ─────────────────────────────────────────────────────────────
    /**
     * Called by extension.ts when a vulnerability is first detected.
     */
    async reportDetection(finding) {
        const event = this.buildEvent(finding, types_js_1.DeveloperAction.DETECTED);
        await this.enqueue(event);
    }
    /**
     * Called when the developer takes an action on a finding (Explain / Fix / Ignore).
     */
    async reportAction(finding, action) {
        const event = this.buildEvent(finding, action);
        await this.enqueue(event);
    }
    /**
     * Get the current session ID (used to group events in one coding session).
     */
    getSessionId() {
        return this.sessionId;
    }
    // ─── Private ─────────────────────────────────────────────────────────────────
    buildEvent(finding, action) {
        const config = vscode.workspace.getConfiguration('sentinel');
        return {
            eventId: finding.id,
            developerId: config.get('developerId') ?? 'DEV001',
            sessionId: this.sessionId,
            vulnerabilityType: finding.type,
            severity: finding.severity,
            confidence: finding.confidence,
            fileName: finding.fileName,
            lineNumber: finding.lineNumber,
            action,
            timestamp: new Date().toISOString(),
        };
    }
    async enqueue(event) {
        this.queue.push({ event, retries: 0 });
        this.scheduleFlush();
    }
    scheduleFlush() {
        if (this.flushTimer !== undefined) {
            return; // already scheduled
        }
        this.flushTimer = setTimeout(() => {
            this.flushTimer = undefined;
            void this.flush();
        }, 1000); // batch sends every 1 second
    }
    async flush() {
        if (this.queue.length === 0) {
            return;
        }
        const config = vscode.workspace.getConfiguration('sentinel');
        const backendUrl = config.get('backendUrl') ?? 'http://localhost:3000';
        const url = `${backendUrl}/api/security-events`;
        const toSend = [...this.queue];
        this.queue = [];
        for (const item of toSend) {
            try {
                await this.post(url, item.event);
            }
            catch {
                // Re-queue with retry counter
                if (item.retries < 3) {
                    this.queue.push({ event: item.event, retries: item.retries + 1 });
                }
                // After 3 retries, silently drop (don't crash extension over backend issues)
            }
        }
        // If there are still items waiting (from failures), schedule another flush
        if (this.queue.length > 0) {
            setTimeout(() => void this.flush(), 5000);
        }
    }
    async post(url, body) {
        // Use dynamic import to avoid ESM/CJS issues in VS Code extension host
        const { default: fetch } = await import('node-fetch');
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(5000), // 5-second timeout
        });
        if (!response.ok) {
            throw new Error(`Backend returned ${response.status}`);
        }
    }
    generateSessionId() {
        return `SESSION-${Date.now()}-${Math.random().toString(36).substring(2, 9).toUpperCase()}`;
    }
    dispose() {
        if (this.flushTimer !== undefined) {
            clearTimeout(this.flushTimer);
        }
    }
}
exports.SecurityEventClient = SecurityEventClient;
//# sourceMappingURL=securityEventClient.js.map