/**
 * Intelligent Feedback Engine — Score Calculator
 *
 * Calculates a developer's security score (0–100) based on their
 * vulnerability history and generates trend information.
 *
 * Score formula (mirrors the Sentinel dashboard's score logic):
 *   score = 100 - (CRITICAL×25 + HIGH×10 + MEDIUM×5 + LOW×2)
 *   clamped to [0, 100]
 *
 * The score is recalculated on every feedback request based on the
 * developer's full historical encounter data.
 */

import { DeveloperProfile, SecurityScore, ScoreTrend, Severity } from '../types';

// ─── Severity weights ────────────────────────────────────────────────────────

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 25,
  HIGH:     10,
  MEDIUM:    5,
  LOW:       2,
  INFO:      0,
};

// How many recent encounters to consider for the "current" score
// (avoids punishing old fixed issues too harshly)
const RECENT_ENCOUNTER_WINDOW = 20;

// ─── Calculator ──────────────────────────────────────────────────────────────

export class ScoreCalculator {

  /**
   * Calculate the current security score and trend for a developer profile.
   *
   * @param profile - The developer's full profile
   * @param newSeverity - The severity of the finding just detected (included in calc)
   * @returns A SecurityScore with score, trend, delta, and summary message
   */
  calculate(profile: DeveloperProfile, newSeverity: Severity): SecurityScore {
    const rawScore = this.computeRawScore(profile, newSeverity);
    const clamped  = Math.max(0, Math.min(100, rawScore));

    const previous = profile.currentScore;
    const delta    = clamped - previous;
    const trend    = this.computeTrend(delta);
    const summary  = this.buildSummary(clamped, delta, trend);

    return {
      score:   clamped,
      trend,
      delta,
      summary,
    };
  }

  /**
   * Calculate a score from a flat list of severities (used by profile endpoint).
   * This is a simplified version that scores against the raw history list.
   */
  calculateFromFindings(severities: Severity[]): SecurityScore {
    let penalty = 0;
    const recent = severities.slice(-RECENT_ENCOUNTER_WINDOW);
    for (const sev of recent) {
      penalty += SEVERITY_WEIGHTS[sev] ?? 0;
    }
    const score  = Math.max(0, Math.min(100, 100 - penalty));
    const trend: ScoreTrend = 'stable';
    return {
      score,
      trend,
      delta:   0,
      summary: this.buildSummary(score, 0, trend),
    };
  }

  // ─── Private ───────────────────────────────────────────────────────────────

  private computeRawScore(profile: DeveloperProfile, newSeverity: Severity): number {
    // Gather all recent encounter severities across all vulnerability types
    const recentSeverities: Severity[] = [];

    for (const stats of Object.values(profile.vulnerabilityStats)) {
      if (!stats) { continue; }

      // Take the last N entries from history
      const slice = stats.history.slice(-RECENT_ENCOUNTER_WINDOW);
      for (const entry of slice) {
        recentSeverities.push(entry.severity);
      }
    }

    // Include the current finding
    recentSeverities.push(newSeverity);

    // Accumulate penalty
    let penalty = 0;
    for (const sev of recentSeverities) {
      penalty += SEVERITY_WEIGHTS[sev] ?? 0;
    }

    return 100 - penalty;
  }

  private computeTrend(delta: number): ScoreTrend {
    if (delta > 2)  { return 'declining';  } // score went down (penalty increased)
    if (delta < -2) { return 'improving';  } // score went up (fewer recent findings)
    return 'stable';
  }

  private buildSummary(score: number, delta: number, trend: ScoreTrend): string {
    if (score >= 90) {
      return `🏆 Excellent security posture! Score: ${score}/100`;
    }
    if (score >= 75) {
      return `✅ Good security practices. Score: ${score}/100`;
    }
    if (score >= 50) {
      const trendStr = trend === 'declining'
        ? `⚠️ Score dropped by ${Math.abs(delta)} — fix recurring issues.`
        : '';
      return `🟠 Moderate security issues detected. Score: ${score}/100. ${trendStr}`.trim();
    }
    if (score >= 25) {
      return `🔴 Significant security vulnerabilities. Score: ${score}/100 — immediate attention required.`;
    }
    return `🚨 Critical security posture. Score: ${score}/100 — multiple severe vulnerabilities detected.`;
  }
}
