"use strict";
/**
 * Sentinel — Project Store
 *
 * Manages Projects, Shifts, and ShiftSessions.
 * All data is persisted to sentinel/src/DATA/:
 *   projects.json       — all projects
 *   shifts.json         — all shifts
 *   shift_sessions.json — all completed + active sessions
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
exports.ProjectStore = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
// ─── Project Store ─────────────────────────────────────────────────────────────
class ProjectStore {
    constructor(extensionPath) {
        // In-memory caches
        this.projects = [];
        this.shifts = [];
        this.sessions = [];
        this.dataDir = path.join(extensionPath, 'src', 'DATA');
        if (!fs.existsSync(this.dataDir)) {
            fs.mkdirSync(this.dataDir, { recursive: true });
        }
        this.load();
    }
    // ─── Projects ───────────────────────────────────────────────────────────────
    createProject(name, description, supervisorId, supervisorName) {
        const project = {
            id: `proj-${Date.now()}`,
            name: name.trim(),
            description: description.trim(),
            supervisorId,
            supervisorName,
            createdAt: new Date().toISOString(),
            status: 'active',
        };
        this.projects.push(project);
        this.flushProjects();
        return project;
    }
    getProjects(supervisorId) {
        this.loadProjects();
        if (supervisorId) {
            return this.projects.filter(p => p.supervisorId === supervisorId);
        }
        return [...this.projects];
    }
    getProject(projectId) {
        this.loadProjects();
        return this.projects.find(p => p.id === projectId);
    }
    updateProjectStatus(projectId, status) {
        this.loadProjects();
        const p = this.projects.find(p => p.id === projectId);
        if (!p) {
            return false;
        }
        p.status = status;
        this.flushProjects();
        return true;
    }
    deleteProject(projectId) {
        this.loadProjects();
        const idx = this.projects.findIndex(p => p.id === projectId);
        if (idx === -1) {
            return false;
        }
        this.projects.splice(idx, 1);
        this.flushProjects();
        return true;
    }
    // ─── Shifts ─────────────────────────────────────────────────────────────────
    createShift(projectId, name, description, scheduledStart, scheduledEnd, assignedDeveloperIds, assignedDeveloperNames, createdBy) {
        const project = this.getProject(projectId);
        if (!project) {
            return null;
        }
        const shift = {
            id: `shift-${Date.now()}`,
            projectId,
            projectName: project.name,
            name: name.trim(),
            description: description.trim(),
            scheduledStart,
            scheduledEnd,
            assignedDeveloperIds,
            assignedDeveloperNames,
            status: 'scheduled',
            createdAt: new Date().toISOString(),
            createdBy,
        };
        this.shifts.push(shift);
        this.flushShifts();
        return shift;
    }
    getShifts(projectId) {
        this.loadShifts();
        if (projectId) {
            return this.shifts.filter(s => s.projectId === projectId);
        }
        return [...this.shifts];
    }
    /** Get all shifts assigned to a specific developer */
    getShiftsForDeveloper(developerId) {
        this.loadShifts();
        return this.shifts.filter(s => s.assignedDeveloperIds.includes(developerId));
    }
    getShift(shiftId) {
        this.loadShifts();
        return this.shifts.find(s => s.id === shiftId);
    }
    updateShiftStatus(shiftId, status) {
        this.loadShifts();
        const s = this.shifts.find(s => s.id === shiftId);
        if (!s) {
            return false;
        }
        s.status = status;
        this.flushShifts();
        return true;
    }
    updateShiftAssignments(shiftId, developerIds, developerNames) {
        this.loadShifts();
        const s = this.shifts.find(s => s.id === shiftId);
        if (!s) {
            return false;
        }
        s.assignedDeveloperIds = developerIds;
        s.assignedDeveloperNames = developerNames;
        this.flushShifts();
        return true;
    }
    deleteShift(shiftId) {
        this.loadShifts();
        const idx = this.shifts.findIndex(s => s.id === shiftId);
        if (idx === -1) {
            return false;
        }
        this.shifts.splice(idx, 1);
        this.flushShifts();
        return true;
    }
    // ─── Shift Sessions ──────────────────────────────────────────────────────────
    /** Start a new shift session for a developer */
    startSession(shift, developerId, developerUsername, developerDisplayName, githubAvatarUrl) {
        this.loadSessions();
        // Mark any previously active session for this dev as ended (safety)
        for (const s of this.sessions) {
            if (s.developerId === developerId && s.endedAt === null) {
                s.endedAt = new Date().toISOString();
                s.summary = this.generateSummary(s);
            }
        }
        const session = {
            id: `sess-${Date.now()}`,
            shiftId: shift.id,
            shiftName: shift.name,
            projectId: shift.projectId,
            projectName: shift.projectName,
            developerId,
            developerUsername,
            developerDisplayName,
            githubAvatarUrl,
            startedAt: new Date().toISOString(),
            endedAt: null,
            findings: [],
            summary: null,
        };
        this.sessions.push(session);
        this.flushSessions();
        // Mark shift as active
        this.updateShiftStatus(shift.id, 'active');
        return session;
    }
    /** Add a finding to an active session */
    addFindingToSession(sessionId, finding) {
        this.loadSessions();
        const session = this.sessions.find(s => s.id === sessionId);
        if (!session || session.endedAt !== null) {
            return;
        }
        // Deduplicate by finding id
        if (!session.findings.find(f => f.id === finding.id)) {
            session.findings.push(finding);
            this.flushSessions();
        }
    }
    /** End a shift session and generate its summary */
    endSession(sessionId) {
        this.loadSessions();
        const session = this.sessions.find(s => s.id === sessionId);
        if (!session) {
            return null;
        }
        session.endedAt = new Date().toISOString();
        session.summary = this.generateSummary(session);
        this.flushSessions();
        // Check if all developers have ended — then mark shift completed
        this.checkShiftCompletion(session.shiftId);
        return session;
    }
    /** Get the active (not yet ended) session for a developer */
    getActiveSession(developerId) {
        this.loadSessions();
        return this.sessions.find(s => s.developerId === developerId && s.endedAt === null) ?? null;
    }
    /** Get all sessions for a shift */
    getSessionsForShift(shiftId) {
        this.loadSessions();
        return this.sessions.filter(s => s.shiftId === shiftId);
    }
    /** Get all completed sessions for a developer */
    getSessionsForDeveloper(developerId) {
        this.loadSessions();
        return this.sessions
            .filter(s => s.developerId === developerId && s.endedAt !== null)
            .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
    }
    /** Get all sessions (for supervisor overview) */
    getAllSessions() {
        this.loadSessions();
        return [...this.sessions];
    }
    // ─── Summary Generation ──────────────────────────────────────────────────────
    generateSummary(session) {
        const findings = session.findings;
        const byType = {};
        const filesSet = new Set();
        let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0, infoCount = 0;
        for (const f of findings) {
            byType[f.type] = (byType[f.type] ?? 0) + 1;
            filesSet.add(path.basename(f.fileName));
            switch (f.severity) {
                case 'CRITICAL':
                    criticalCount++;
                    break;
                case 'HIGH':
                    highCount++;
                    break;
                case 'MEDIUM':
                    mediumCount++;
                    break;
                case 'LOW':
                    lowCount++;
                    break;
                default:
                    infoCount++;
                    break;
            }
        }
        const start = new Date(session.startedAt).getTime();
        const end = session.endedAt ? new Date(session.endedAt).getTime() : Date.now();
        const durationMinutes = Math.round((end - start) / 60000);
        // Security score: start at 100, deduct per finding
        const securityScore = Math.max(0, Math.min(100, 100
            - criticalCount * 20
            - highCount * 10
            - mediumCount * 4
            - lowCount * 1));
        const recommendations = this.buildRecommendations(byType, findings.length, durationMinutes);
        return {
            totalFindings: findings.length,
            criticalCount,
            highCount,
            mediumCount,
            lowCount,
            infoCount,
            byType,
            filesAffected: [...filesSet],
            durationMinutes,
            securityScore,
            trend: securityScore >= 80 ? 'improving' : securityScore >= 50 ? 'stable' : 'declining',
            recommendations,
            generatedAt: new Date().toISOString(),
        };
    }
    buildRecommendations(byType, total, durationMinutes) {
        const recs = [];
        if ((byType['SQL_INJECTION'] ?? 0) >= 2) {
            recs.push('Consistently use parameterized queries / prepared statements for all database operations.');
        }
        if ((byType['XSS'] ?? 0) >= 1) {
            recs.push('Replace innerHTML/dangerouslySetInnerHTML with textContent or sanitize with DOMPurify.');
        }
        if ((byType['HARDCODED_SECRET'] ?? 0) >= 1) {
            recs.push('Move all secrets to environment variables or a secrets manager (AWS Secrets Manager, Vault).');
        }
        if ((byType['COMMAND_INJECTION'] ?? 0) >= 1) {
            recs.push('Use execFile() with array arguments instead of exec() with shell strings.');
        }
        if (total > 15) {
            recs.push('High vulnerability density detected. Consider a dedicated secure code review session.');
        }
        if (durationMinutes > 0 && total === 0) {
            recs.push('Excellent session — no vulnerabilities detected! Keep following secure coding practices.');
        }
        if (recs.length === 0) {
            recs.push('Good session. Continue reviewing OWASP Top 10 patterns to maintain your security score.');
        }
        return recs;
    }
    checkShiftCompletion(shiftId) {
        const shift = this.getShift(shiftId);
        if (!shift) {
            return;
        }
        // If all assigned developers have ended their sessions, mark shift completed
        const sessions = this.getSessionsForShift(shiftId);
        const endedCount = sessions.filter(s => s.endedAt !== null).length;
        if (endedCount >= shift.assignedDeveloperIds.length && endedCount > 0) {
            this.updateShiftStatus(shiftId, 'completed');
        }
    }
    // ─── Persistence ────────────────────────────────────────────────────────────
    load() {
        this.loadProjects();
        this.loadShifts();
        this.loadSessions();
    }
    loadProjects() {
        try {
            const raw = fs.readFileSync(path.join(this.dataDir, 'projects.json'), 'utf8');
            this.projects = JSON.parse(raw);
        }
        catch {
            this.projects = [];
        }
    }
    loadShifts() {
        try {
            const raw = fs.readFileSync(path.join(this.dataDir, 'shifts.json'), 'utf8');
            this.shifts = JSON.parse(raw);
        }
        catch {
            this.shifts = [];
        }
    }
    loadSessions() {
        try {
            const raw = fs.readFileSync(path.join(this.dataDir, 'shift_sessions.json'), 'utf8');
            this.sessions = JSON.parse(raw);
        }
        catch {
            this.sessions = [];
        }
    }
    flushProjects() {
        this.write('projects.json', this.projects);
    }
    flushShifts() {
        this.write('shifts.json', this.shifts);
    }
    flushSessions() {
        this.write('shift_sessions.json', this.sessions);
    }
    write(filename, data) {
        try {
            fs.writeFileSync(path.join(this.dataDir, filename), JSON.stringify(data, null, 2), 'utf8');
        }
        catch (err) {
            console.error(`[ProjectStore] Failed to write ${filename}:`, err);
        }
    }
}
exports.ProjectStore = ProjectStore;
//# sourceMappingURL=projectStore.js.map