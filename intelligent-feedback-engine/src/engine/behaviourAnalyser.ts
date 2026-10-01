/**
 * Intelligent Feedback Engine — Behaviour Analyser
 *
 * Analyses a developer's history to determine:
 *   1. The feedback escalation level (FIRST_TIME → REPEATED → PERSISTENT → CRITICAL_PATTERN)
 *   2. Recurring patterns across vulnerability types
 *   3. Context strings to guide the AI prompt
 *
 * Escalation thresholds:
 *   totalEncounters = 1            → FIRST_TIME
 *   totalEncounters = 2–3          → REPEATED
 *   totalEncounters = 4–6          → PERSISTENT
 *   totalEncounters >= 7           → CRITICAL_PATTERN
 */

import {
  DeveloperProfile,
  FeedbackLevel,
  VulnerabilityType,
  VulnerabilityStats,
} from '../types';

// ─── Thresholds ───────────────────────────────────────────────────────────────

const REPEATED_THRESHOLD         = 2;  // >= 2 → REPEATED
const PERSISTENT_THRESHOLD       = 4;  // >= 4 → PERSISTENT
const CRITICAL_PATTERN_THRESHOLD = 7;  // >= 7 → CRITICAL_PATTERN

// ─── Analysis Result ──────────────────────────────────────────────────────────

export interface BehaviourAnalysis {
  /** Escalation level based on encounter count */
  feedbackLevel: FeedbackLevel;
  /** Total times this vuln type has been seen for this developer */
  totalEncounters: number;
  /** Times seen in the current session */
  sessionEncounters: number;
  /** Human-readable escalation message (terse, shown as VS Code notification) */
  escalationMessage: string;
  /** Rich context string describing the developer's history — fed into the AI prompt */
  developerContext: string;
  /** Optional motivational message if developer has improved elsewhere */
  motivationalMessage?: string;
  /** Recurring vulnerability types the developer struggles with (for context) */
  recurringWeaknesses: VulnerabilityType[];
}

// ─── Analyser ─────────────────────────────────────────────────────────────────

export class BehaviourAnalyser {

  /**
   * Analyse a developer's profile in the context of the current finding.
   *
   * @param profile           - Full developer profile from the ProfileStore
   * @param vulnerabilityType - The type of the vulnerability just detected
   * @param sessionId         - Current session ID
   * @returns BehaviourAnalysis with level, messages, and AI context strings
   */
  analyse(
    profile: DeveloperProfile,
    vulnerabilityType: VulnerabilityType,
    sessionId: string,
  ): BehaviourAnalysis {
    const stats = profile.vulnerabilityStats[vulnerabilityType];

    // Treat as first encounter if no history exists yet (the record will be added after analysis)
    const totalEncounters   = stats ? stats.totalEncounters + 1 : 1;
    const sessionEncounters = stats ? stats.sessionEncounters + 1 : 1;

    const feedbackLevel   = this.computeLevel(totalEncounters);
    const escalationMessage = this.buildEscalationMessage(
      vulnerabilityType, feedbackLevel, totalEncounters, sessionEncounters,
    );

    const recurringWeaknesses = this.findRecurringWeaknesses(profile, vulnerabilityType);
    const developerContext    = this.buildDeveloperContext(
      profile, vulnerabilityType, totalEncounters, sessionEncounters, recurringWeaknesses,
    );

    const motivationalMessage = this.buildMotivationalMessage(profile, vulnerabilityType);

    return {
      feedbackLevel,
      totalEncounters,
      sessionEncounters,
      escalationMessage,
      developerContext,
      motivationalMessage,
      recurringWeaknesses,
    };
  }

  // ─── Private — Escalation Level ───────────────────────────────────────────

  private computeLevel(totalEncounters: number): FeedbackLevel {
    if (totalEncounters >= CRITICAL_PATTERN_THRESHOLD) { return 'CRITICAL_PATTERN'; }
    if (totalEncounters >= PERSISTENT_THRESHOLD)       { return 'PERSISTENT';       }
    if (totalEncounters >= REPEATED_THRESHOLD)         { return 'REPEATED';         }
    return 'FIRST_TIME';
  }

  // ─── Private — Escalation Message ─────────────────────────────────────────

  private buildEscalationMessage(
    type: VulnerabilityType,
    level: FeedbackLevel,
    total: number,
    session: number,
  ): string {
    const typeName = this.formatTypeName(type);

    switch (level) {
      case 'FIRST_TIME':
        return `🛡 Sentinel detected ${typeName}. Here's what you need to know.`;

      case 'REPEATED':
        return `⚠️ ${typeName} detected again (${total}× total). ` +
               `Make sure to apply the fix — this is becoming a pattern.`;

      case 'PERSISTENT':
        return `🔴 ${typeName} is a recurring issue (${total}× total, ${session}× this session). ` +
               `Please review the recommended fix carefully.`;

      case 'CRITICAL_PATTERN':
        return `🚨 CRITICAL PATTERN: ${typeName} has been detected ${total} times. ` +
               `This is a systematic vulnerability in your code. Immediate action required.`;
    }
  }

  // ─── Private — Developer Context for AI ───────────────────────────────────

  private buildDeveloperContext(
    profile: DeveloperProfile,
    currentType: VulnerabilityType,
    totalEncounters: number,
    sessionEncounters: number,
    recurringWeaknesses: VulnerabilityType[],
  ): string {
    const lines: string[] = [];

    lines.push(`Developer ID: ${profile.developerId}`);
    lines.push(`Total sessions: ${profile.sessions.length}`);
    lines.push(`Overall security score: ${profile.currentScore}/100`);
    lines.push('');
    lines.push(`Current vulnerability type: ${currentType}`);
    lines.push(`  - Total encounters (all time): ${totalEncounters}`);
    lines.push(`  - Encounters this session: ${sessionEncounters}`);

    if (totalEncounters > 1) {
      const stats = profile.vulnerabilityStats[currentType];
      if (stats?.firstSeenAt) {
        lines.push(`  - First seen: ${stats.firstSeenAt}`);
      }
    }

    if (recurringWeaknesses.length > 0) {
      lines.push('');
      lines.push('Other recurring vulnerabilities this developer struggles with:');
      for (const w of recurringWeaknesses) {
        const wStats = profile.vulnerabilityStats[w];
        if (wStats) {
          lines.push(`  - ${w}: ${wStats.totalEncounters} encounters`);
        }
      }
    }

    // Summarise vulnerability history across all types
    const allTypes = Object.keys(profile.vulnerabilityStats) as VulnerabilityType[];
    if (allTypes.length > 1) {
      lines.push('');
      lines.push('Full vulnerability history summary:');
      for (const t of allTypes) {
        const s = profile.vulnerabilityStats[t] as VulnerabilityStats;
        lines.push(`  - ${t}: ${s.totalEncounters} total encounters`);
      }
    }

    return lines.join('\n');
  }

  // ─── Private — Motivational Message ───────────────────────────────────────

  /**
   * If the developer has improved in OTHER vulnerability types, acknowledge it.
   * This is only returned when meaningful (i.e., they fixed something before).
   */
  private buildMotivationalMessage(
    profile: DeveloperProfile,
    currentType: VulnerabilityType,
  ): string | undefined {
    const allTypes = Object.keys(profile.vulnerabilityStats) as VulnerabilityType[];

    // Find types where the developer has had encounters but none recently (sign of improvement)
    const improvedTypes = allTypes.filter(t => {
      if (t === currentType) { return false; }
      const stats = profile.vulnerabilityStats[t];
      if (!stats || stats.totalEncounters === 0) { return false; }
      // "Improved" = had encounters but session count is 0 (not seen this session)
      return stats.sessionEncounters === 0 && stats.totalEncounters >= 2;
    });

    if (improvedTypes.length > 0) {
      const typeName = this.formatTypeName(improvedTypes[0]);
      return `💪 You haven't introduced ${typeName} this session — great progress! Apply the same discipline here.`;
    }

    // First time for everything? Be encouraging
    if (profile.totalFeedbackCount <= 1) {
      return `👋 Welcome to Sentinel! Security awareness is the first step — you're on the right track.`;
    }

    return undefined;
  }

  // ─── Private — Recurring Weakness Detection ────────────────────────────────

  /**
   * Returns vulnerability types (other than the current one) where
   * totalEncounters >= REPEATED_THRESHOLD — indicating a pattern.
   */
  private findRecurringWeaknesses(
    profile: DeveloperProfile,
    currentType: VulnerabilityType,
  ): VulnerabilityType[] {
    const weaknesses: VulnerabilityType[] = [];

    for (const [type, stats] of Object.entries(profile.vulnerabilityStats)) {
      if (type === currentType || !stats) { continue; }
      if (stats.totalEncounters >= REPEATED_THRESHOLD) {
        weaknesses.push(type as VulnerabilityType);
      }
    }

    // Sort by encounter count descending
    weaknesses.sort((a, b) => {
      const sa = profile.vulnerabilityStats[a]?.totalEncounters ?? 0;
      const sb = profile.vulnerabilityStats[b]?.totalEncounters ?? 0;
      return sb - sa;
    });

    return weaknesses.slice(0, 3); // Return top 3 recurring weaknesses at most
  }

  // ─── Private — Formatting ─────────────────────────────────────────────────

  private formatTypeName(type: VulnerabilityType): string {
    const names: Record<string, string> = {
      SQL_INJECTION:            'SQL Injection',
      XSS:                      'Cross-Site Scripting (XSS)',
      HARDCODED_SECRET:         'Hardcoded Secret',
      COMMAND_INJECTION:        'Command Injection',
      PATH_TRAVERSAL:           'Path Traversal',
      MISSING_INPUT_VALIDATION: 'Missing Input Validation',
      UNSAFE_DESERIALIZATION:   'Unsafe Deserialization',
      WEAK_CRYPTOGRAPHY:        'Weak Cryptography',
      INSECURE_AUTH:            'Insecure Authentication',
      SENSITIVE_DATA_EXPOSURE:  'Sensitive Data Exposure',
    };
    return names[type] ?? type.replace(/_/g, ' ');
  }
}
