/**
 * Intelligent Feedback Engine — REST API Routes
 *
 * Endpoints:
 *
 *   POST   /api/feedback/request           → Main entry point from Sentinel
 *   GET    /api/feedback/profile/:id       → Full developer profile + score
 *   GET    /api/feedback/history/:id       → Vulnerability encounter history
 *   GET    /api/feedback/leaderboard       → All developers ranked by score
 *   GET    /api/health                     → Health check
 */

import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { ProfileStore } from '../data/profileStore';
import { BehaviourAnalyser } from '../engine/behaviourAnalyser';
import { FeedbackGenerator } from '../engine/feedbackGenerator';
import { ScoreCalculator } from '../engine/scoreCalculator';
import {
  FeedbackRequest,
  FeedbackResponse,
  VulnerabilityHistoryEntry,
  VulnerabilityType,
  Severity,
} from '../types';
import * as path from 'path';

// ─── Initialise Singletons ───────────────────────────────────────────────────

const dataRoot        = path.join(__dirname, '..', '..', 'data');
const profileStore    = new ProfileStore(dataRoot);
const behaviourAnalyser  = new BehaviourAnalyser();
const feedbackGenerator  = new FeedbackGenerator();
const scoreCalculator    = new ScoreCalculator();

export const router = Router();

// ─── POST /api/feedback/request ───────────────────────────────────────────────

/**
 * Main endpoint called by Sentinel (Component 1) after every vulnerability detection.
 *
 * Flow:
 *   1. Validate request body
 *   2. Load developer profile from store
 *   3. Analyse behaviour (escalation level, patterns)
 *   4. Generate AI-powered contextual explanation + fix
 *   5. Calculate updated security score
 *   6. Persist encounter to profile
 *   7. Return FeedbackResponse to Sentinel
 */
router.post('/request', async (req: Request, res: Response): Promise<void> => {
  const startTime = Date.now();

  try {
    const body = req.body as Partial<FeedbackRequest>;

    // ── Validation ──────────────────────────────────────────────────────────
    const required: (keyof FeedbackRequest)[] = [
      'developerId', 'sessionId', 'vulnerabilityType',
      'severity', 'codeSnippet', 'fileName', 'lineNumber',
    ];
    const missing = required.filter(k => body[k] === undefined || body[k] === '');
    if (missing.length > 0) {
      res.status(400).json({
        status: 'error',
        error: `Missing required fields: ${missing.join(', ')}`,
      } as Partial<FeedbackResponse>);
      return;
    }

    const feedbackReq = body as FeedbackRequest;

    // ── Load Profile ─────────────────────────────────────────────────────────
    const profile = profileStore.getProfile(feedbackReq.developerId);

    // ── Behaviour Analysis ───────────────────────────────────────────────────
    const analysis = behaviourAnalyser.analyse(
      profile,
      feedbackReq.vulnerabilityType as VulnerabilityType,
      feedbackReq.sessionId,
    );

    // ── AI Feedback Generation ───────────────────────────────────────────────
    const generated = await feedbackGenerator.generate(
      feedbackReq.codeSnippet,
      feedbackReq.vulnerabilityType as VulnerabilityType,
      feedbackReq.severity as Severity,
      analysis,
      feedbackReq.fileName,
      feedbackReq.lineNumber,
    );

    // ── Score Calculation ────────────────────────────────────────────────────
    const scoreResult = scoreCalculator.calculate(profile, feedbackReq.severity as Severity);

    // ── Persist Encounter ────────────────────────────────────────────────────
    const historyEntry: VulnerabilityHistoryEntry = {
      detectedAt:    feedbackReq.timestamp ?? new Date().toISOString(),
      sessionId:     feedbackReq.sessionId,
      severity:      feedbackReq.severity as Severity,
      confidence:    feedbackReq.confidence ?? 1.0,
      codeSnippet:   feedbackReq.codeSnippet,
      fileBaseName:  feedbackReq.fileName.split('/').pop() ?? feedbackReq.fileName,
      lineNumber:    feedbackReq.lineNumber,
      feedbackLevel: analysis.feedbackLevel,
    };

    profileStore.recordEncounter(
      feedbackReq.developerId,
      feedbackReq.sessionId,
      feedbackReq.vulnerabilityType as VulnerabilityType,
      historyEntry,
    );
    profileStore.updateScore(feedbackReq.developerId, scoreResult.score);

    // ── Build Response ───────────────────────────────────────────────────────
    const response: FeedbackResponse = {
      status:                 'ok',
      feedbackLevel:          analysis.feedbackLevel,
      escalationMessage:      analysis.escalationMessage,
      contextualExplanation:  generated.contextualExplanation,
      personalizedFix:        generated.personalizedFix,
      motivationalMessage:    analysis.motivationalMessage,
      securityScore:          scoreResult.score,
      scoreTrend:             scoreResult.trend,
      aiGenerated:            generated.aiGenerated,
    };

    const elapsed = Date.now() - startTime;
    console.log(
      `[POST /feedback/request] dev=${feedbackReq.developerId} ` +
      `type=${feedbackReq.vulnerabilityType} ` +
      `level=${analysis.feedbackLevel} ` +
      `score=${scoreResult.score} ` +
      `ai=${generated.aiGenerated} ` +
      `${elapsed}ms`,
    );

    res.status(200).json(response);

  } catch (err: unknown) {
    console.error('[POST /feedback/request] Unexpected error:', err);
    const message = err instanceof Error ? err.message : 'Internal server error';
    res.status(500).json({ status: 'error', error: message } as Partial<FeedbackResponse>);
  }
});

// ─── GET /api/feedback/profile/:developerId ───────────────────────────────────

/**
 * Returns the full developer profile including all vulnerability stats and score.
 * Used by Sentinel's dashboard (Component 1) and Analytics Dashboard (Component 4).
 */
router.get('/profile/:developerId', (req: Request, res: Response): void => {
  try {
    const { developerId } = req.params;

    if (!developerId || developerId.trim() === '') {
      res.status(400).json({ error: 'developerId is required' });
      return;
    }

    const profile = profileStore.getProfile(developerId);
    const allFindings = gatherAllFindings(profile);
    const score = scoreCalculator.calculateFromFindings(allFindings);

    res.status(200).json({
      profile,
      score,
    });

  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Internal server error';
    res.status(500).json({ error: message });
  }
});

// ─── GET /api/feedback/history/:developerId ──────────────────────────────────

/**
 * Returns the vulnerability encounter history for a developer.
 * Optionally filter by ?type=SQL_INJECTION
 */
router.get('/history/:developerId', (req: Request, res: Response): void => {
  try {
    const { developerId } = req.params;
    const typeFilter = req.query['type'] as VulnerabilityType | undefined;

    const profile = profileStore.getProfile(developerId);
    const stats   = profile.vulnerabilityStats;

    if (typeFilter) {
      // Return history for a specific vulnerability type
      const typeStat = stats[typeFilter];
      res.status(200).json({
        developerId,
        vulnerabilityType: typeFilter,
        totalEncounters:   typeStat?.totalEncounters ?? 0,
        history:           typeStat?.history ?? [],
      });
    } else {
      // Return a summary across all types
      const summary = Object.entries(stats).map(([type, s]) => ({
        vulnerabilityType: type,
        totalEncounters:   s?.totalEncounters ?? 0,
        firstSeenAt:       s?.firstSeenAt,
        lastSeenAt:        s?.lastSeenAt,
        historyCount:      s?.history.length ?? 0,
      }));

      res.status(200).json({
        developerId,
        currentScore:   profile.currentScore,
        totalSessions:  profile.sessions.length,
        summary,
      });
    }

  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Internal server error';
    res.status(500).json({ error: message });
  }
});

// ─── GET /api/feedback/leaderboard ───────────────────────────────────────────

/**
 * Returns all developer profiles ranked by security score (highest first).
 * Designed for Component 4 (Analytics Dashboard).
 */
router.get('/leaderboard', (_req: Request, res: Response): void => {
  try {
    const allProfiles = profileStore.getAllProfiles();

    const leaderboard = allProfiles
      .map(p => ({
        developerId:        p.developerId,
        currentScore:       p.currentScore,
        previousScore:      p.previousScore,
        scoreDelta:         p.currentScore - p.previousScore,
        totalFeedbackCount: p.totalFeedbackCount,
        totalSessions:      p.sessions.length,
        updatedAt:          p.updatedAt,
        vulnerabilityTypes: Object.keys(p.vulnerabilityStats).length,
      }))
      .sort((a, b) => b.currentScore - a.currentScore);

    res.status(200).json({
      count: leaderboard.length,
      leaderboard,
    });

  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Internal server error';
    res.status(500).json({ error: message });
  }
});

// ─── GET /api/health ──────────────────────────────────────────────────────────

router.get('/health', (_req: Request, res: Response): void => {
  res.status(200).json({
    status:    'ok',
    service:   'Intelligent Feedback Engine',
    version:   '1.0.0',
    component: 'Member 3',
    timestamp: new Date().toISOString(),
    groqEnabled: !!(process.env.GROQ_API_KEY && process.env.GROQ_API_KEY !== 'your_groq_api_key_here'),
    profilesDir: profileStore.getProfilesDir(),
  });
});

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Flatten all history entries from a profile into a single array (for score calc).
 */
function gatherAllFindings(profile: ReturnType<ProfileStore['getProfile']>): Severity[] {
  const severities: Severity[] = [];
  for (const stats of Object.values(profile.vulnerabilityStats)) {
    if (!stats) { continue; }
    for (const entry of stats.history) {
      severities.push(entry.severity);
    }
  }
  return severities;
}
