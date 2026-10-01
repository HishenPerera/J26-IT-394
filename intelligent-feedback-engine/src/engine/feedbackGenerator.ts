/**
 * Intelligent Feedback Engine — AI Feedback Generator
 *
 * Uses the Groq SDK (llama-3.1-8b-instant) to generate contextual,
 * personalised security feedback tailored to:
 *   1. The developer's actual vulnerable code snippet
 *   2. Their behaviour history (escalation level, recurring patterns)
 *
 * If GROQ_API_KEY is not set or Groq is unavailable, the generator
 * falls back to high-quality rule-based explanations — the service
 * never goes down because of a missing API key.
 *
 * Output shape (parsed from Groq's JSON response):
 *   {
 *     contextualExplanation: string,   // WHY this specific code is vulnerable
 *     personalizedFix: string,         // How to fix THIS specific snippet
 *   }
 */

import Groq from 'groq-sdk';
import { FeedbackLevel, VulnerabilityType, Severity } from '../types';
import { BehaviourAnalysis } from './behaviourAnalyser';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface GeneratedFeedback {
  contextualExplanation: string;
  personalizedFix: string;
  aiGenerated: boolean;
}

// ─── Generator ────────────────────────────────────────────────────────────────

export class FeedbackGenerator {
  private groq: Groq | null = null;
  private readonly model = 'llama-3.1-8b-instant';

  constructor() {
    const apiKey = process.env.GROQ_API_KEY;
    if (apiKey && apiKey !== 'your_groq_api_key_here') {
      this.groq = new Groq({ apiKey });
      console.log('[FeedbackGenerator] Groq AI enabled.');
    } else {
      console.warn('[FeedbackGenerator] No GROQ_API_KEY found — using rule-based fallback.');
    }
  }

  /**
   * Generate contextual explanation and personalised fix for a vulnerability.
   *
   * @param codeSnippet       - The developer's actual vulnerable code
   * @param vulnerabilityType - Type of vulnerability detected
   * @param severity          - Severity of the finding
   * @param analysis          - Behaviour analysis (escalation level, context)
   * @param fileName          - Name of the file (for context)
   * @param lineNumber        - Line number in the file
   */
  async generate(
    codeSnippet: string,
    vulnerabilityType: VulnerabilityType,
    severity: Severity,
    analysis: BehaviourAnalysis,
    fileName: string,
    lineNumber: number,
  ): Promise<GeneratedFeedback> {
    if (this.groq) {
      try {
        return await this.generateWithGroq(
          codeSnippet, vulnerabilityType, severity, analysis, fileName, lineNumber,
        );
      } catch (err) {
        console.error('[FeedbackGenerator] Groq call failed, using fallback:', err);
      }
    }

    // Fallback to rule-based explanations
    return this.generateFallback(codeSnippet, vulnerabilityType, severity, analysis);
  }

  // ─── Groq AI Generation ─────────────────────────────────────────────────────

  private async generateWithGroq(
    codeSnippet: string,
    vulnerabilityType: VulnerabilityType,
    severity: Severity,
    analysis: BehaviourAnalysis,
    fileName: string,
    lineNumber: number,
  ): Promise<GeneratedFeedback> {

    const systemPrompt = this.buildSystemPrompt(analysis.feedbackLevel);
    const userPrompt   = this.buildUserPrompt(
      codeSnippet, vulnerabilityType, severity, analysis, fileName, lineNumber,
    );

    const completion = await this.groq!.chat.completions.create({
      model: this.model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user',   content: userPrompt   },
      ],
      temperature: 0.3,    // Lower temperature = more precise, consistent output
      max_tokens:  800,
      response_format: { type: 'json_object' },
    });

    const content = completion.choices[0]?.message?.content ?? '{}';
    const parsed  = JSON.parse(content) as {
      contextualExplanation?: string;
      personalizedFix?: string;
    };

    return {
      contextualExplanation: parsed.contextualExplanation ?? this.fallbackExplanation(vulnerabilityType),
      personalizedFix:       parsed.personalizedFix       ?? this.fallbackFix(vulnerabilityType, codeSnippet),
      aiGenerated: true,
    };
  }

  // ─── Prompt Building ────────────────────────────────────────────────────────

  private buildSystemPrompt(level: FeedbackLevel): string {
    const toneMap: Record<FeedbackLevel, string> = {
      FIRST_TIME:       'Be friendly, educational, and encouraging. Explain clearly without being condescending.',
      REPEATED:         'Be firm but constructive. Point out the pattern without being harsh. Emphasise the fix.',
      PERSISTENT:       'Be direct and urgent. This developer keeps making the same mistake. Be clear about consequences.',
      CRITICAL_PATTERN: 'Be very direct and serious. This is a systematic security blind spot that must be fixed immediately.',
    };

    return `You are a senior application security engineer providing real-time, personalized code review feedback 
inside a VS Code extension called Sentinel. 

Your tone for this response: ${toneMap[level]}

You MUST respond with ONLY valid JSON in exactly this shape:
{
  "contextualExplanation": "<2-3 sentences explaining WHY the developer's specific code is vulnerable. Reference the actual code. Do NOT be generic.>",
  "personalizedFix": "<A concrete, specific fix for their exact code. Include the corrected code snippet if possible. Be precise.>"
}

Rules:
- Reference the actual code snippet provided — never give generic explanations
- Keep contextualExplanation under 150 words
- Keep personalizedFix under 150 words and include a code example
- Use plain text, no markdown formatting inside the JSON strings
- Do NOT include any text outside the JSON object`;
  }

  private buildUserPrompt(
    codeSnippet: string,
    vulnerabilityType: VulnerabilityType,
    severity: Severity,
    analysis: BehaviourAnalysis,
    fileName: string,
    lineNumber: number,
  ): string {
    return `VULNERABILITY DETECTED:
Type: ${vulnerabilityType}
Severity: ${severity}
File: ${fileName.split('/').pop() ?? fileName}
Line: ${lineNumber}

VULNERABLE CODE (the developer wrote this):
\`\`\`
${codeSnippet}
\`\`\`

DEVELOPER HISTORY:
${analysis.developerContext}

This developer has encountered ${vulnerabilityType} ${analysis.totalEncounters} time(s) total.
Feedback level: ${analysis.feedbackLevel}

Generate a contextual explanation and personalised fix for THIS specific code.`;
  }

  // ─── Rule-Based Fallback ─────────────────────────────────────────────────────

  private generateFallback(
    codeSnippet: string,
    vulnerabilityType: VulnerabilityType,
    severity: Severity,
    analysis: BehaviourAnalysis,
  ): GeneratedFeedback {
    return {
      contextualExplanation: this.fallbackExplanation(vulnerabilityType),
      personalizedFix:       this.fallbackFix(vulnerabilityType, codeSnippet),
      aiGenerated: false,
    };
  }

  private fallbackExplanation(type: VulnerabilityType): string {
    const explanations: Partial<Record<VulnerabilityType, string>> = {
      SQL_INJECTION:
        'Your code directly concatenates user input into an SQL query string. An attacker can ' +
        'inject SQL metacharacters (e.g. \' OR 1=1 --) to alter the query logic, bypass ' +
        'authentication, or exfiltrate data from your database.',
      XSS:
        'Your code inserts user-controlled data directly into the DOM via innerHTML or similar. ' +
        'An attacker can inject a <script> tag or event handler that executes in the victim\'s ' +
        'browser, stealing cookies or performing actions on their behalf.',
      HARDCODED_SECRET:
        'A secret credential is embedded directly in your source code. Anyone with read access ' +
        'to the repository — or a compiled binary — can extract this value. Even after removal, ' +
        'it remains in git history and must be rotated immediately.',
      COMMAND_INJECTION:
        'User-supplied input is passed to a shell command without sanitisation. An attacker can ' +
        'append shell metacharacters (e.g. ; rm -rf /) to execute arbitrary OS commands on your server.',
      PATH_TRAVERSAL:
        'A file path is built using unsanitised user input. An attacker can use ../ sequences ' +
        'to escape the intended directory and read sensitive files such as /etc/passwd or private keys.',
    };
    return (
      explanations[type] ??
      `This code contains a ${type.replace(/_/g, ' ')} vulnerability that could allow attackers ` +
      `to compromise your application's security.`
    );
  }

  private fallbackFix(type: VulnerabilityType, _snippet: string): string {
    const fixes: Partial<Record<VulnerabilityType, string>> = {
      SQL_INJECTION:
        'Use parameterized queries (prepared statements). Example (C#): ' +
        'var cmd = new SqlCommand("SELECT * FROM Users WHERE Id=@id", conn); ' +
        'cmd.Parameters.AddWithValue("@id", userId);',
      XSS:
        'Replace innerHTML with textContent for plain text: element.textContent = userInput; ' +
        'If you must render HTML, sanitise first: element.innerHTML = DOMPurify.sanitize(userInput);',
      HARDCODED_SECRET:
        'Move the secret to an environment variable: process.env.MY_SECRET (Node.js) or ' +
        'Environment.GetEnvironmentVariable("MY_SECRET") (C#). Add a .env file and gitignore it.',
      COMMAND_INJECTION:
        'Pass arguments as an array instead of a shell string: ' +
        'execFile("ping", [userInput]) instead of exec("ping " + userInput);',
      PATH_TRAVERSAL:
        'Canonicalize and validate the resolved path: ' +
        'const resolved = path.resolve(baseDir, userInput); ' +
        'if (!resolved.startsWith(baseDir)) throw new Error("Invalid path");',
    };
    return (
      fixes[type] ??
      `Apply the secure coding pattern for ${type.replace(/_/g, ' ')} as documented by OWASP.`
    );
  }
}
