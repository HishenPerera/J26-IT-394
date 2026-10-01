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

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

// ─── Types ────────────────────────────────────────────────────────────────────

export type UserRole = 'developer' | 'supervisor' | 'administrator';

export interface User {
  id: string;
  username: string;
  passwordHash: string;
  role: UserRole;
  displayName: string;
  email: string;
  createdAt: string;
}

export interface AuthSession {
  userId: string;
  username: string;
  displayName: string;
  role: UserRole;
  email: string;
  loggedInAt: string;
}

const SESSION_KEY = 'sentinel.authSession';
const USERS_FILE = 'users.json';

// ─── AuthManager ──────────────────────────────────────────────────────────────

export class AuthManager {
  private users: User[] = [];
  private readonly dataDir: string;

  constructor(private readonly context: vscode.ExtensionContext) {
    this.dataDir = path.join(context.extensionPath, 'src', 'data');
    this.loadUsers();
  }

  // ── User Store ──────────────────────────────────────────────────────────────

  private loadUsers(): void {
    try {
      const filePath = path.join(this.dataDir, USERS_FILE);
      const raw = fs.readFileSync(filePath, 'utf8');
      this.users = JSON.parse(raw) as User[];
    } catch {
      this.users = [];
    }
  }

  private saveUsers(): void {
    try {
      const filePath = path.join(this.dataDir, USERS_FILE);
      fs.writeFileSync(filePath, JSON.stringify(this.users, null, 2), 'utf8');
    } catch {
      // Ignore write errors in read-only environments
    }
  }

  getAllUsers(): Omit<User, 'passwordHash'>[] {
    // Reload from disk each time to pick up admin changes
    this.loadUsers();
    return this.users.map(({ passwordHash: _ph, ...u }) => u);
  }

  // ── Crypto ──────────────────────────────────────────────────────────────────

  static hashPassword(password: string): string {
    return crypto.createHash('sha256').update(password).digest('hex');
  }

  // ── Authentication ──────────────────────────────────────────────────────────

  /**
   * Attempt to authenticate with username + password.
   * Returns the session on success, or null on failure.
   */
  login(username: string, password: string): AuthSession | null {
    this.loadUsers(); // always reload for freshness
    const hash = AuthManager.hashPassword(password);
    const user = this.users.find(
      u => u.username === username && u.passwordHash === hash
    );

    if (!user) {
      return null;
    }

    const session: AuthSession = {
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

  logout(): void {
    void this.context.workspaceState.update(SESSION_KEY, undefined);
  }

  getSession(): AuthSession | undefined {
    return this.context.workspaceState.get<AuthSession>(SESSION_KEY);
  }

  isLoggedIn(): boolean {
    return !!this.getSession();
  }

  // ── Admin: User Management ──────────────────────────────────────────────────

  addUser(
    username: string,
    password: string,
    role: UserRole,
    displayName: string,
    email: string
  ): { success: boolean; message: string } {
    this.loadUsers();

    if (this.users.find(u => u.username === username)) {
      return { success: false, message: `Username "${username}" already exists.` };
    }

    const newUser: User = {
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

  removeUser(userId: string): { success: boolean; message: string } {
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
