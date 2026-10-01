"use strict";
/**
 * Sentinel — Auth Manager
 *
 * Handles credential verification and session management for the
 * role-based login system. Uses Node.js built-in `crypto` (SHA-256)
 * — no external dependencies required.
 *
 * Roles: developer | supervisor | administrator
 * Sessions: stored in ExtensionContext.workspaceState
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
const SESSION_KEY = 'sentinel.authSession';
const USERS_FILE = 'users.json';
// ─── AuthManager ──────────────────────────────────────────────────────────────
class AuthManager {
    constructor(context) {
        this.context = context;
        this.users = [];
        this.dataDir = path.join(context.extensionPath, 'src', 'data');
        this.loadUsers();
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
        // Reload from disk each time to pick up admin changes
        this.loadUsers();
        return this.users.map(({ passwordHash: _ph, ...u }) => u);
    }
    // ── Crypto ──────────────────────────────────────────────────────────────────
    static hashPassword(password) {
        return crypto.createHash('sha256').update(password).digest('hex');
    }
    // ── Authentication ──────────────────────────────────────────────────────────
    /**
     * Attempt to authenticate with username + password.
     * Returns the session on success, or null on failure.
     */
    login(username, password) {
        this.loadUsers(); // always reload for freshness
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
        };
        // Persist to workspace state
        void this.context.workspaceState.update(SESSION_KEY, session);
        return session;
    }
    logout() {
        void this.context.workspaceState.update(SESSION_KEY, undefined);
    }
    getSession() {
        return this.context.workspaceState.get(SESSION_KEY);
    }
    isLoggedIn() {
        return !!this.getSession();
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
        // Prevent removing the last admin
        if (removed.role === 'administrator' && this.users.filter(u => u.role === 'administrator').length <= 1) {
            return { success: false, message: 'Cannot remove the last administrator.' };
        }
        this.users.splice(idx, 1);
        this.saveUsers();
        return { success: true, message: `User "${removed.username}" removed.` };
    }
}
exports.AuthManager = AuthManager;
//# sourceMappingURL=authManager.js.map