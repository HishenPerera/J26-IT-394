/**
 * Intelligent Feedback Engine — Core Types
 *
 * These are the shared type contracts used across all modules.
 * The FeedbackRequest/FeedbackResponse types form the API contract
 * between Component 1 (Sentinel) and Component 3 (this service).
 */

// ─── Enums ────────────────────────────────────────────────────────────────────

/** Severity levels — mirrors Sentinel's Severity enum */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

/** Vulnerability types — mirrors Sentinel's VulnerabilityType enum */
export type VulnerabilityType =
  | 'SQL_INJECTION'
  | 'XSS'
  | 'HARDCODED_SECRET'
  | 'COMMAND_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'MISSING_INPUT_VALIDATION'
  | 'UNSAFE_DESERIALIZATION'
  | 'WEAK_CRYPTOGRAPHY'
  | 'INSECURE_AUTH'
  | 'SENSITIVE_DATA_EXPOSURE';

/**
 * Feedback escalation level — determined by how many times the developer
 * has encountered (and not fixed) the same vulnerability type.
 *
 * FIRST_TIME      → Friendly, educational tone. Full explanation.
 * REPEATED        → Firmer tone. Emphasises the pattern. Shows fix.
 * PERSISTENT      → Urgent tone. Developer is repeatedly ignoring this.
 * CRITICAL_PATTERN → Alert. This developer has a systematic blind spot.
 */
export type FeedbackLevel =
  | 'FIRST_TIME'
  | 'REPEATED'
  | 'PERSISTENT'
  | 'CRITICAL_PATTERN';

/** Trend direction for security score */
export type ScoreTrend = 'improving' | 'declining' | 'stable';

// ─── API Request / Response ───────────────────────────────────────────────────

/**
 * Payload sent from Sentinel (Component 1) to POST /api/feedback/request.
 * Mirrors the SecurityFinding + SecurityEvent shapes in Sentinel's types.ts.
 */
export interface FeedbackRequest {
  /** Developer identifier (from sentinel.developerId config or GitHub username) */
  developerId: string;
  /** Session identifier from Sentinel's SecurityEventClient */
  sessionId: string;
  /** The vulnerability category detected */
  vulnerabilityType: VulnerabilityType;
  /** Severity of the finding */
  severity: Severity;
  /** Confidence score 0.0–1.0 */
  confidence: number;
  /** The actual vulnerable code snippet from the developer's file */
  codeSnippet: string;
  /** Absolute path of the affected file */
  fileName: string;
  /** 1-indexed line number of the vulnerability */
  lineNumber: number;
  /** ISO 8601 timestamp of detection */
  timestamp: string;
}

/**
 * Response returned from the Intelligent Feedback Engine to Sentinel.
 * Sentinel uses this to show adaptive notifications and populate the dashboard.
 */
export interface FeedbackResponse {
  /** OK or ERROR */
  status: 'ok' | 'error';

  /** Escalation level based on developer history */
  feedbackLevel: FeedbackLevel;

  /**
   * Short, level-appropriate escalation message to show as a VS Code notification.
   * e.g. "You've introduced SQL Injection 3 times — time to fix this permanently."
   */
  escalationMessage: string;

  /**
   * AI-generated contextual explanation of WHY this specific code is vulnerable.
   * Tailored to the actual code snippet, not a generic description.
   */
  contextualExplanation: string;

  /**
   * AI-generated personalised secure code fix specific to the detected snippet.
   */
  personalizedFix: string;

  /**
   * Optional motivational message acknowledging past improvements.
   * e.g. "You fixed XSS last session — you can do this too."
   */
  motivationalMessage?: string;

  /** Developer's current security score (0–100) */
  securityScore: number;

  /** Whether the score is going up, down, or flat */
  scoreTrend: ScoreTrend;

  /** Whether the AI (Groq) was used or rule-based fallback was used */
  aiGenerated: boolean;

  /** Error message if status is 'error' */
  error?: string;
}

// ─── Developer Profile ────────────────────────────────────────────────────────

/**
 * A single entry in the developer's vulnerability encounter history.
 */
export interface VulnerabilityHistoryEntry {
  /** ISO 8601 timestamp of detection */
  detectedAt: string;
  /** Session this was detected in */
  sessionId: string;
  /** Severity of the finding */
  severity: Severity;
  /** Confidence score */
  confidence: number;
  /** The code snippet (for AI context) */
  codeSnippet: string;
  /** File name (basename only, for privacy) */
  fileBaseName: string;
  /** Line number */
  lineNumber: number;
  /** Feedback level assigned at this encounter */
  feedbackLevel: FeedbackLevel;
}

/**
 * Per-vulnerability-type statistics tracked for a developer.
 */
export interface VulnerabilityStats {
  /** Total number of times this vulnerability type was detected */
  totalEncounters: number;
  /** Number of encounters in the current session */
  sessionEncounters: number;
  /** ISO 8601 timestamp of first encounter */
  firstSeenAt: string;
  /** ISO 8601 timestamp of most recent encounter */
  lastSeenAt: string;
  /** Historical encounter records (last 50 kept) */
  history: VulnerabilityHistoryEntry[];
}

/**
 * The full persisted developer profile.
 * One file per developer: `data/profiles/<developerId>.json`
 */
export interface DeveloperProfile {
  /** Developer identifier */
  developerId: string;
  /** ISO 8601 timestamp of profile creation */
  createdAt: string;
  /** ISO 8601 timestamp of last update */
  updatedAt: string;
  /** Map from VulnerabilityType string to per-type statistics */
  vulnerabilityStats: Partial<Record<VulnerabilityType, VulnerabilityStats>>;
  /** Current security score (0–100) */
  currentScore: number;
  /** Score at the start of the last session (for trend calculation) */
  previousScore: number;
  /** Total number of feedback requests processed for this developer */
  totalFeedbackCount: number;
  /** All session IDs seen for this developer */
  sessions: string[];
}

// ─── Security Score ───────────────────────────────────────────────────────────

export interface SecurityScore {
  /** 0–100 score */
  score: number;
  /** Direction of change */
  trend: ScoreTrend;
  /** Change in score since last session (+12, -5, 0) */
  delta: number;
  /** Human-readable summary */
  summary: string;
}
