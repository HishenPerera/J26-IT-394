/**
 * Intelligent Feedback Engine — Developer Profile Store
 *
 * Persists and retrieves DeveloperProfile objects as JSON files.
 * One file per developer: data/profiles/<developerId>.json
 *
 * The store is the single source of truth for:
 *   - Vulnerability encounter history per developer
 *   - Security scores
 *   - Session tracking
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  DeveloperProfile,
  VulnerabilityType,
  VulnerabilityStats,
  VulnerabilityHistoryEntry,
} from '../types';

// Maximum history entries kept per vulnerability type (older ones are pruned)
const MAX_HISTORY_PER_TYPE = 50;

export class ProfileStore {
  private readonly profilesDir: string;

  /** In-memory cache: developerId → profile (avoids repeated disk reads in a session) */
  private cache: Map<string, DeveloperProfile> = new Map();

  /**
   * @param dataRootPath - Absolute path to the `data/` directory.
   *   The store will create `data/profiles/` automatically if needed.
   */
  constructor(dataRootPath: string) {
    this.profilesDir = path.join(dataRootPath, 'profiles');
    this.ensureDir(this.profilesDir);
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * Load a developer profile from disk (or return a fresh one if new developer).
   */
  getProfile(developerId: string): DeveloperProfile {
    if (this.cache.has(developerId)) {
      return this.cache.get(developerId)!;
    }

    const filePath = this.profilePath(developerId);
    if (fs.existsSync(filePath)) {
      try {
        const raw = fs.readFileSync(filePath, 'utf-8');
        const profile = JSON.parse(raw) as DeveloperProfile;
        this.cache.set(developerId, profile);
        return profile;
      } catch {
        // Corrupt file — start fresh
        console.warn(`[ProfileStore] Corrupt profile for ${developerId}, resetting.`);
      }
    }

    const fresh = this.createFreshProfile(developerId);
    this.cache.set(developerId, fresh);
    return fresh;
  }

  /**
   * Load all developer profiles from disk.
   * Used by the leaderboard endpoint.
   */
  getAllProfiles(): DeveloperProfile[] {
    const profiles: DeveloperProfile[] = [];

    if (!fs.existsSync(this.profilesDir)) {
      return profiles;
    }

    const files = fs.readdirSync(this.profilesDir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const raw = fs.readFileSync(path.join(this.profilesDir, file), 'utf-8');
        profiles.push(JSON.parse(raw) as DeveloperProfile);
      } catch {
        // Skip corrupt files
      }
    }

    return profiles;
  }

  /**
   * Record a new vulnerability encounter for a developer and persist it to disk.
   *
   * @param developerId        - The developer who owns this finding
   * @param sessionId          - Current coding session ID
   * @param vulnerabilityType  - Type of vulnerability detected
   * @param historyEntry       - Full encounter details
   * @returns The updated profile
   */
  recordEncounter(
    developerId: string,
    sessionId: string,
    vulnerabilityType: VulnerabilityType,
    historyEntry: VulnerabilityHistoryEntry,
  ): DeveloperProfile {
    const profile = this.getProfile(developerId);
    const now = new Date().toISOString();

    // Track session
    if (!profile.sessions.includes(sessionId)) {
      profile.sessions.push(sessionId);
    }

    // Initialise per-type stats if this is first encounter
    if (!profile.vulnerabilityStats[vulnerabilityType]) {
      profile.vulnerabilityStats[vulnerabilityType] = {
        totalEncounters: 0,
        sessionEncounters: 0,
        firstSeenAt: now,
        lastSeenAt: now,
        history: [],
      };
    }

    const stats = profile.vulnerabilityStats[vulnerabilityType] as VulnerabilityStats;

    // Update stats
    stats.totalEncounters += 1;
    stats.sessionEncounters += 1;
    stats.lastSeenAt = now;

    // Append history (cap at MAX_HISTORY_PER_TYPE)
    stats.history.push(historyEntry);
    if (stats.history.length > MAX_HISTORY_PER_TYPE) {
      stats.history = stats.history.slice(stats.history.length - MAX_HISTORY_PER_TYPE);
    }

    // Update profile metadata
    profile.updatedAt = now;
    profile.totalFeedbackCount += 1;

    // Persist to disk
    this.save(profile);
    return profile;
  }

  /**
   * Update the developer's security score in the profile and persist.
   */
  updateScore(developerId: string, newScore: number): void {
    const profile = this.getProfile(developerId);
    profile.previousScore = profile.currentScore;
    profile.currentScore = newScore;
    profile.updatedAt = new Date().toISOString();
    this.save(profile);
  }

  /**
   * Reset session encounter counts for all vulnerability types.
   * Call this when a new session begins (detected by a new sessionId).
   */
  resetSessionCounts(developerId: string, sessionId: string): void {
    const profile = this.getProfile(developerId);

    // Only reset if this is genuinely a new session
    if (profile.sessions.includes(sessionId)) {
      return;
    }

    for (const type of Object.keys(profile.vulnerabilityStats) as VulnerabilityType[]) {
      const stats = profile.vulnerabilityStats[type];
      if (stats) {
        stats.sessionEncounters = 0;
      }
    }

    this.save(profile);
  }

  /**
   * Returns the absolute path to the profiles directory (for logging).
   */
  getProfilesDir(): string {
    return this.profilesDir;
  }

  // ─── Private ─────────────────────────────────────────────────────────────────

  private save(profile: DeveloperProfile): void {
    try {
      const filePath = this.profilePath(profile.developerId);
      fs.writeFileSync(filePath, JSON.stringify(profile, null, 2), 'utf-8');
      this.cache.set(profile.developerId, profile);
    } catch (err) {
      console.error(`[ProfileStore] Failed to save profile for ${profile.developerId}:`, err);
    }
  }

  private profilePath(developerId: string): string {
    // Sanitise the ID to avoid path traversal (only allow alphanumeric + _ - .)
    const safe = developerId.replace(/[^a-zA-Z0-9_\-.]/g, '_');
    return path.join(this.profilesDir, `${safe}.json`);
  }

  private createFreshProfile(developerId: string): DeveloperProfile {
    return {
      developerId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      vulnerabilityStats: {},
      currentScore: 100,
      previousScore: 100,
      totalFeedbackCount: 0,
      sessions: [],
    };
  }

  private ensureDir(dirPath: string): void {
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
    }
  }
}
