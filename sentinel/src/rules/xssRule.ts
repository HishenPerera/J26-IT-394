/**
 * Sentinel — XSS (Cross-Site Scripting) Rule
 *
 * Detects unsafe patterns that inject user-controlled data into the DOM.
 */

import { v4 as uuidv4 } from '../util/uuid.js';
import {
  SecurityFinding,
  SecurityRule,
  Severity,
  VulnerabilityType,
} from '../analyzer/types.js';

interface XssPattern {
  regex: RegExp;
  confidence: number;
  message: string;
}

const XSS_PATTERNS: XssPattern[] = [
  // innerHTML / outerHTML assignment
  {
    regex: /\.innerHTML\s*=\s*(?!["'`]<[^>]+>["'`])\S/g,
    confidence: 0.90,
    message: '`innerHTML` assignment with non-static value — possible XSS if value contains user input.',
  },
  {
    regex: /\.outerHTML\s*=\s*\w/g,
    confidence: 0.88,
    message: '`outerHTML` assignment with variable — possible XSS.',
  },
  // document.write with variable
  {
    regex: /document\.write\s*\(\s*(?!\s*["'`][^"'`]*["'`]\s*\))\w/g,
    confidence: 0.87,
    message: '`document.write()` with variable input — possible XSS.',
  },
  // eval with variable
  {
    regex: /\beval\s*\(\s*\w/g,
    confidence: 0.95,
    message: '`eval()` with variable — extremely dangerous, potential code injection.',
  },
  // setTimeout / setInterval with string
  {
    regex: /(?:setTimeout|setInterval)\s*\(\s*\w[^,)]+,/g,
    confidence: 0.75,
    message: '`setTimeout/setInterval` with string argument — avoid eval-like patterns.',
  },
  // React dangerouslySetInnerHTML
  {
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/g,
    confidence: 0.80,
    message: '`dangerouslySetInnerHTML` used — ensure HTML is sanitized before rendering.',
  },
  // jQuery .html() with variable
  {
    regex: /\$\([^)]+\)\.html\s*\(\s*\w/g,
    confidence: 0.85,
    message: 'jQuery `.html()` with variable — possible XSS if value contains user input.',
  },
];

const SUPPORTED_LANGUAGES = [
  'javascript',
  'typescript',
  'javascriptreact',
  'typescriptreact',
  'html',
  'php',
  'plaintext',
];

export class XssRule implements SecurityRule {
  readonly ruleId = 'SENTINEL-XSS-001';
  readonly ruleName = 'XSS Detector';
  readonly vulnerabilityType = VulnerabilityType.XSS;
  readonly supportedLanguages = SUPPORTED_LANGUAGES;

  analyze(text: string, fileName: string, languageId: string): SecurityFinding[] {
    if (!this.supportedLanguages.includes(languageId)) {
      return [];
    }

    const findings: SecurityFinding[] = [];
    const lines = text.split('\n');
    const now = new Date().toISOString();

    for (const pattern of XSS_PATTERNS) {
      pattern.regex.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = pattern.regex.exec(text)) !== null) {
        const beforeMatch = text.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;
        const lastNewline = beforeMatch.lastIndexOf('\n');
        const columnNumber = match.index - (lastNewline === -1 ? 0 : lastNewline + 1);

        const lineContent = lines[lineNumber - 1] || '';

        if (lineContent.trim().startsWith('//') || lineContent.trim().startsWith('*')) {
          continue;
        }

        const alreadyFound = findings.some(
          f => f.lineNumber === lineNumber && f.type === VulnerabilityType.XSS
        );
        if (alreadyFound) {
          continue;
        }

        findings.push({
          id: uuidv4(),
          type: VulnerabilityType.XSS,
          severity: Severity.HIGH,
          confidence: pattern.confidence,
          message: pattern.message,
          fileName,
          lineNumber,
          columnNumber,
          codeSnippet: lineContent.trim(),
          detectedAt: now,
          detectedByRule: this.ruleId,
          rangeStart: match.index,
          rangeEnd: match.index + match[0].length,
        });
      }
    }

    return findings;
  }
}
