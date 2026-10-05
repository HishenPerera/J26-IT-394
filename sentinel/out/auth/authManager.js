"use strict";
/**
 * Sentinel — Auth Manager  (v2 — GitHub OAuth + Password fallback)
 *
 * Authentication flow:
 *   PRIMARY  → GitHub OAuth via VS Code's built-in authentication provider.
 *              On success, fetches the GitHub user profile, auto-provisions
 *              a local user record (role = 'developer' for new accounts),
 *              and creates an AuthSession enriched with GitHub metadata.
 *
 *   FALLBACK → Username + SHA-256 password hash against users.json.
 *              Used by supervisors and administrators who may not have GitHub.
 *
 * Sessions are persisted to workspaceState so they survive panel close/reopen.
 * GitHub sessions are refreshed silently on every activation.
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
exports.AuthManager = void 0;
const crypto = __importStar(require("crypto"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const vscode = __importStar(require("vscode"));
const SESSION_KEY = 'sentinel.authSession';
const USERS_FILE = 'users.json';
// GitHub OAuth scopes we need:
//   read:user  → access profile (login, name, avatar)
//   user:email → access primary email
const GITHUB_SCOPES = ['read:user', 'user:email'];
// ─── AuthManager ──────────────────────────────────────────────────────────────
class AuthManager {
    constructor(context) {
        this.context = context;
        this.users = [];
        this.dataDir = path.join(context.extensionPath, 'src', 'data');
        this.loadUsers();
    }
    // ── GitHub OAuth Authentication ──────────────────────────────────────────────
    /**
     * Attempt to authenticate via GitHub OAuth.
     *
     * Behaviour:
     *   - If `silent = true`, tries to reuse an existing GitHub session without
     *     showing a UI prompt. Used during activate() to restore login state.
     *   - If `silent = false`, shows the VS Code "Sign in with GitHub" prompt.
     *
     * On success:
     *   1. Fetches the GitHub user profile via the REST API.
     *   2. Auto-provisions a local user record if none exists for this GitHub login.
     *   3. Updates the cached avatar URL and display name.
     *   4. Persists the AuthSession.
     *
     * @returns The new AuthSession on success, or null on failure/cancellation.
     */
    async loginWithGitHub(silent = false) {
        try {
            const vsSession = await vscode.authentication.getSession('github', GITHUB_SCOPES, { silent, createIfNone: !silent });
            if (!vsSession) {
                return null; // User cancelled or silent refresh found nothing
            }
            const profile = await this.fetchGitHubProfile(vsSession.accessToken);
            if (!profile) {
                return null;
            }
            // Find or auto-provision a local user for this GitHub account
            const user = this.findOrProvisionGitHubUser(profile);
            const session = {
                userId: user.id,
                username: user.username,
                displayName: profile.name ?? profile.login,
                role: user.role,
                email: profile.email ?? user.email,
                loggedInAt: new Date().toISOString(),
                authMethod: 'github',
                githubUsername: profile.login,
                githubAvatarUrl: profile.avatar_url,
                githubName: profile.name ?? profile.login,
                githubAccessToken: vsSession.accessToken,
            };
            await this.context.workspaceState.update(SESSION_KEY, session);
            console.log(`[AuthManager] GitHub login: ${profile.login} → role: ${user.role}`);
            return session;
        }
        catch (err) {
            // User dismissed the sign-in dialog
            if (err?.message?.includes('User did not consent')) {
                return null;
            }
            console.error('[AuthManager] GitHub login error:', err);
            return null;
        }
    }
    /**
     * Silently refresh GitHub session on extension activate.
     * Restores the active session without prompting if one already exists.
     */
    async refreshGitHubSession() {
        return this.loginWithGitHub(true);
    }
    // ── Password Authentication (fallback) ──────────────────────────────────────
    /**
     * Authenticate with username + password (SHA-256).
     * Used for supervisor and administrator accounts.
     */
    login(username, password) {
        this.loadUsers();
        const hash = AuthManager.hashPassword(password);
        const user = this.users.find(u => u.username === username && u.passwordHash === hash);
        if (!user) {
            return null;
        }
        const session = {
            userId: user.id,
            username: user.username,
            displayName: user.displayName,
            role: user.role,
            email: user.email,
            loggedInAt: new Date().toISOString(),
            authMethod: 'password',
        };
        void this.context.workspaceState.update(SESSION_KEY, session);
        return session;
    }
    // ── Session Management ───────────────────────────────────────────────────────
    logout() {
        void this.context.workspaceState.update(SESSION_KEY, undefined);
    }
    getSession() {
        return this.context.workspaceState.get(SESSION_KEY);
    }
    isLoggedIn() {
        return !!this.getSession();
    }
    // ── User Store ──────────────────────────────────────────────────────────────
    loadUsers() {
        try {
            const filePath = path.join(this.dataDir, USERS_FILE);
            const raw = fs.readFileSync(filePath, 'utf8');
            this.users = JSON.parse(raw);
        }
        catch {
            this.users = [];
        }
    }
    saveUsers() {
        try {
            const filePath = path.join(this.dataDir, USERS_FILE);
            fs.writeFileSync(filePath, JSON.stringify(this.users, null, 2), 'utf8');
        }
        catch {
            // Ignore write errors in read-only environments
        }
    }
    getAllUsers() {
        this.loadUsers();
        return this.users.map(({ passwordHash: _ph, ...u }) => u);
    }
    // ── Crypto ──────────────────────────────────────────────────────────────────
    static hashPassword(password) {
        return crypto.createHash('sha256').update(password).digest('hex');
    }
    // ── Admin: User Management ──────────────────────────────────────────────────
    addUser(username, password, role, displayName, email) {
        this.loadUsers();
        if (this.users.find(u => u.username === username)) {
            return { success: false, message: `Username "${username}" already exists.` };
        }
        const newUser = {
            id: `user-${role.substring(0, 3)}-${Date.now()}`,
            username,
            passwordHash: AuthManager.hashPassword(password),
            role,
            displayName,
            email,
            createdAt: new Date().toISOString(),
        };
        this.users.push(newUser);
        this.saveUsers();
        return { success: true, message: `User "${username}" created successfully.` };
    }
    removeUser(userId) {
        this.loadUsers();
        const idx = this.users.findIndex(u => u.id === userId);
        if (idx === -1) {
            return { success: false, message: 'User not found.' };
        }
        const removed = this.users[idx];
        if (removed.role === 'administrator' &&
            this.users.filter(u => u.role === 'administrator').length <= 1) {
            return { success: false, message: 'Cannot remove the last administrator.' };
        }
        this.users.splice(idx, 1);
        this.saveUsers();
        return { success: true, message: `User "${removed.username}" removed.` };
    }
    // ── Private: GitHub Helpers ──────────────────────────────────────────────────
    /**
     * Call the GitHub REST API to fetch the authenticated user's profile.
     */
    async fetchGitHubProfile(accessToken) {
        try {
            const response = await fetch('https://api.github.com/user', {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    Accept: 'application/vnd.github+json',
                    'X-GitHub-Api-Version': '2022-11-28',
                    'User-Agent': 'Sentinel-VSCode-Extension',
                },
                signal: AbortSignal.timeout(5000),
            });
            if (!response.ok) {
                console.error(`[AuthManager] GitHub API error: ${response.status}`);
                return null;
            }
            return await response.json();
        }
        catch (err) {
            console.error('[AuthManager] Failed to fetch GitHub profile:', err);
            return null;
        }
    }
    /**
     * Find an existing local user whose githubUsername matches the profile login,
     * or provision a new developer account automatically.
     *
     * Provisioning rules:
     *   - New GitHub users → role: 'developer'
     *   - Existing password users linked by githubUsername → keep their role
     */
    findOrProvisionGitHubUser(profile) {
        this.loadUsers();
        // 1. Look for an existing user already linked to this GitHub account
        let user = this.users.find(u => u.githubUsername === profile.login);
        // 2. Look for a user whose username matches the GitHub login
        if (!user) {
            user = this.users.find(u => u.username === profile.login);
        }
        // 3. Auto-provision a new developer account
        if (!user) {
            user = {
                id: `user-dev-gh-${Date.now()}`,
                username: profile.login,
                passwordHash: '', // GitHub-only accounts have no password
                role: 'developer',
                displayName: profile.name ?? profile.login,
                email: profile.email ?? `${profile.login}@github.com`,
                createdAt: new Date().toISOString(),
                githubUsername: profile.login,
                githubAvatarUrl: profile.avatar_url,
            };
            this.users.push(user);
            console.log(`[AuthManager] Auto-provisioned new developer: ${profile.login}`);
        }
        // 4. Update GitHub metadata on existing user if changed
        if (user.githubUsername !== profile.login || user.githubAvatarUrl !== profile.avatar_url) {
            user.githubUsername = profile.login;
            user.githubAvatarUrl = profile.avatar_url;
            if (!user.displayName || user.displayName === user.username) {
                user.displayName = profile.name ?? profile.login;
            }
        }
        this.saveUsers();
        return user;
    }
}
exports.AuthManager = AuthManager;
//# sourceMappingURL=authManager.js.map