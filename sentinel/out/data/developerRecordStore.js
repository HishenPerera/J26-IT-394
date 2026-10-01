"use strict";
/**
 * Sentinel — Developer Vulnerability Record Store
 *
 * Identifies the developer by checking VS Code's built-in GitHub authentication
 * session first. If the developer is signed into VS Code with GitHub, their
 * GitHub username is used as the developer ID (e.g. "hishenperera").
 * If no GitHub session exists, falls back to the sentinel.developerId
 * workspace setting, then to "DEV_UNKNOWN".
 *
 * File written to:
 *   sentinel/src/DATA/<developerId>_vulnerability_records.json
 *
 * Records are appended on every new detection. Within a single VS Code session,
 * duplicate findings (same finding.id) are skipped to avoid re-writing when
 * the same file is re-analysed.
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
exports.DeveloperRecordStore = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const vscode = __importStar(require("vscode"));
// ─── Store ────────────────────────────────────────────────────────────────────
class DeveloperRecordStore {
    /**
     * @param extensionRootPath - The absolute path to the extension root
     *   (the folder containing package.json). Pass `context.extensionPath` from activate().
     */
    constructor(extensionRootPath) {
        /** Tracks finding IDs already saved in this session to avoid duplicates */
        this.savedFindingIds = new Set();
        /**
         * Cached developer identity after first resolution.
         * null = not yet resolved.
         */
        this.cachedDeveloperId = null;
        /**
         * Cached GitHub username (null if not signed in via GitHub).
         */
        this.cachedGitHubUsername = null;
        // DATA folder sits alongside src/ in the extension root
        this.dataDir = path.join(extensionRootPath, 'src', 'DATA');
        this.ensureDataDir();
    }
    // ─── Public API ─────────────────────────────────────────────────────────────
    /**
     * Save a security finding as a developer vulnerability record.
     *
     * - Resolves the developerId: GitHub username → config → fallback.
     * - Skips if this exact finding has already been saved in the current session.
     * - Appends to the developer's JSON record file.
     *
     * @param finding   - The SecurityFinding from the analyzer.
     * @param sessionId - The current session ID (from SecurityEventClient.getSessionId()).
     */
    async save(finding, sessionId) {
        // Skip duplicates within the same session
        if (this.savedFindingIds.has(finding.id)) {
            return;
        }
        const { developerId, githubUsername } = await this.resolveIdentity();
        const record = this.buildRecord(finding, developerId, githubUsername, sessionId);
        try {
            await this.appendRecord(developerId, record);
            this.savedFindingIds.add(finding.id);
        }
        catch (err) {
            // Never let a write error crash the extension
            console.error('[Sentinel] DeveloperRecordStore: Failed to save record:', err);
        }
    }
    /**
     * Returns the absolute path to the record file for the current developer.
     * Uses the cached developer ID if already resolved, otherwise falls back
     * to the config value (synchronous, safe to call before first save()).
     */
    getRecordFilePath() {
        const developerId = this.cachedDeveloperId ??
            vscode.workspace.getConfiguration('sentinel').get('developerId') ??
            'DEV_UNKNOWN';
        return path.join(this.dataDir, `${developerId}_vulnerability_records.json`);
    }
    /**
     * Dispose — clears the in-session deduplication cache and identity cache.
     */
    dispose() {
        this.savedFindingIds.clear();
        this.cachedDeveloperId = null;
        this.cachedGitHubUsername = null;
    }
    // ─── Private ──────────────────────────────────────────────────────────
    /**
     * Resolve the developer identity for this session.
     *
     * Resolution order:
     *   1. GitHub username (from VS Code's built-in GitHub auth session)
     *   2. sentinel.developerId workspace/user setting
     *   3. "DEV_UNKNOWN" hard fallback
     *
     * The result is cached after the first call so we don't hit the auth
     * API on every finding.
     */
    async resolveIdentity() {
        // Return cached identity if already resolved for this session
        if (this.cachedDeveloperId !== null) {
            return { developerId: this.cachedDeveloperId, githubUsername: this.cachedGitHubUsername };
        }
        let githubUsername = null;
        let developerId;
        try {
            // Ask VS Code for the existing GitHub session — createIfNone: false means
            // we NEVER pop an auth dialog; we silently skip if not logged in.
            const session = await vscode.authentication.getSession('github', // provider ID for GitHub
            ['read:user'], // minimal scope — only need the username
            { createIfNone: false });
            if (session) {
                // session.account.label is the GitHub username (e.g. "hishenperera")
                githubUsername = session.account.label;
                developerId = githubUsername;
                console.log(`[Sentinel] Developer identified via GitHub: ${developerId}`);
            }
            else {
                // Not signed into GitHub — fall back to VS Code setting
                developerId =
                    vscode.workspace
                        .getConfiguration('sentinel')
                        .get('developerId') ?? 'DEV_UNKNOWN';
                console.log(`[Sentinel] No GitHub session; using config developerId: ${developerId}`);
            }
        }
        catch (err) {
            // Auth API failure — degrade gracefully
            console.error('[Sentinel] GitHub auth lookup failed, using config fallback:', err);
            developerId =
                vscode.workspace
                    .getConfiguration('sentinel')
                    .get('developerId') ?? 'DEV_UNKNOWN';
        }
        // Cache for the lifetime of this session
        this.cachedDeveloperId = developerId;
        this.cachedGitHubUsername = githubUsername;
        return { developerId, githubUsername };
    }
    /**
     * Build a fully-typed DeveloperVulnerabilityRecord from a raw SecurityFinding.
     */
    buildRecord(finding, developerId, githubUsername, sessionId) {
        return {
            recordId: this.generateRecordId(),
            developerId,
            githubUsername,
            sessionId,
            vulnerabilityType: finding.type,
            severity: finding.severity,
            confidence: finding.confidence,
            fileName: finding.fileName,
            lineNumber: finding.lineNumber,
            columnNumber: finding.columnNumber,
            codeSnippet: finding.codeSnippet,
            detectedAt: finding.detectedAt,
            detectedByRule: finding.detectedByRule,
            findingId: finding.id,
        };
    }
    /**
     * Load the existing JSON array for this developer (or start fresh),
     * push the new record, and write back atomically.
     */
    async appendRecord(developerId, record) {
        const filePath = path.join(this.dataDir, `${developerId}_vulnerability_records.json`);
        // Load existing records (or start with an empty array)
        let existing = [];
        if (fs.existsSync(filePath)) {
            try {
                const raw = fs.readFileSync(filePath, 'utf-8');
                const parsed = JSON.parse(raw);
                if (Array.isArray(parsed)) {
                    existing = parsed;
                }
            }
            catch {
                // If the file is corrupt, start fresh rather than crashing
                existing = [];
            }
        }
        // Append and write
        existing.push(record);
        fs.writeFileSync(filePath, JSON.stringify(existing, null, 2), 'utf-8');
    }
    /**
     * Ensure the DATA/ directory exists, creating it (and any parents) if needed.
     */
    ensureDataDir() {
        if (!fs.existsSync(this.dataDir)) {
            fs.mkdirSync(this.dataDir, { recursive: true });
        }
    }
    /**
     * Generate a unique record ID.
     * Format: REC-<timestamp>-<5 random uppercase alphanumeric chars>
     */
    generateRecordId() {
        const rand = Math.random().toString(36).substring(2, 7).toUpperCase();
        return `REC-${Date.now()}-${rand}`;
    }
}
exports.DeveloperRecordStore = DeveloperRecordStore;
//# sourceMappingURL=developerRecordStore.js.map