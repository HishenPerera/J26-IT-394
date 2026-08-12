"use strict";
/**
 * Sentinel — SQL Injection Rule
 *
 * Detects unsafe SQL string concatenation patterns.
 * Phase 2: Initial regex-based detection.
 * Phase 7: Will be extended with AST/data-flow analysis.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SqlInjectionRule = void 0;
const uuid_js_1 = require("../util/uuid.js");
const types_js_1 = require("../analyzer/types.js");
const SQL_PATTERNS = [
    // C# / Java / PHP string concatenation into SQL
    {
        regex: /["'`]SELECT\s+.+\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*["'`]\s*\+/gi,
        confidence: 0.95,
        message: 'User-controlled input appears to be concatenated directly into an SQL SELECT query.',
    },
    {
        regex: /["'`]INSERT\s+INTO\s+.+VALUES\s*\(.+["'`]\s*\+/gi,
        confidence: 0.92,
        message: 'User-controlled input appears to be concatenated directly into an SQL INSERT statement.',
    },
    {
        regex: /["'`]UPDATE\s+\w+\s+SET\s+.+["'`]\s*\+/gi,
        confidence: 0.90,
        message: 'User-controlled input appears to be concatenated directly into an SQL UPDATE statement.',
    },
    {
        regex: /["'`]DELETE\s+FROM\s+\w+\s+WHERE\s+.+["'`]\s*\+/gi,
        confidence: 0.93,
        message: 'User-controlled input appears to be concatenated directly into an SQL DELETE statement.',
    },
    // Generic: any SQL keyword followed by string concat with variable
    {
        regex: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+[^;]+["'`]\s*\+\s*\w+/gi,
        confidence: 0.80,
        message: 'Possible SQL injection: SQL string concatenated with a variable.',
    },
    // JavaScript / TypeScript template literal SQL
    {
        regex: /`\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+[^`]*\$\{[^}]+\}/gi,
        confidence: 0.88,
        message: 'SQL query built using a template literal with interpolated variable — possible injection.',
    },
    // Python f-string SQL
    {
        regex: /f["'](?:SELECT|INSERT|UPDATE|DELETE)\s+[^"']*\{[^}]+\}/gi,
        confidence: 0.85,
        message: 'SQL query built using a Python f-string with interpolated variable — possible injection.',
    },
    // .format() or % formatting into SQL
    {
        regex: /["'](?:SELECT|INSERT|UPDATE|DELETE)\s+[^"']*["']\s*%\s*(?:\(|\w)/gi,
        confidence: 0.82,
        message: 'SQL query built using Python % formatting — possible injection.',
    },
    // String.Format in C# / Java
    {
        regex: /String\.Format\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)/gi,
        confidence: 0.88,
        message: 'SQL query built using String.Format() — possible injection if arguments are user-controlled.',
    },
];
// ─── Languages this rule applies to ──────────────────────────────────────────
const SUPPORTED_LANGUAGES = [
    'csharp',
    'java',
    'javascript',
    'typescript',
    'python',
    'php',
    'ruby',
    'go',
    'plaintext', // for testing
];
// ─── Rule Implementation ──────────────────────────────────────────────────────
class SqlInjectionRule {
    constructor() {
        this.ruleId = 'SENTINEL-SQL-001';
        this.ruleName = 'SQL Injection Detector';
        this.vulnerabilityType = types_js_1.VulnerabilityType.SQL_INJECTION;
        this.supportedLanguages = SUPPORTED_LANGUAGES;
    }
    analyze(text, fileName, languageId) {
        if (!this.supportedLanguages.includes(languageId)) {
            return [];
        }
        const findings = [];
        const lines = text.split('\n');
        const now = new Date().toISOString();
        for (const pattern of SQL_PATTERNS) {
            // Reset regex state
            pattern.regex.lastIndex = 0;
            let match;
            while ((match = pattern.regex.exec(text)) !== null) {
                // Calculate line/column from match index
                const beforeMatch = text.substring(0, match.index);
                const lineNumber = beforeMatch.split('\n').length;
                const lastNewline = beforeMatch.lastIndexOf('\n');
                const columnNumber = match.index - (lastNewline === -1 ? 0 : lastNewline + 1);
                // Get the actual line content
                const lineContent = lines[lineNumber - 1] || '';
                // Skip commented lines
                if (this.isCommentedOut(lineContent, languageId)) {
                    continue;
                }
                // Avoid duplicate findings on the same line from different patterns
                const alreadyFound = findings.some(f => f.lineNumber === lineNumber && f.type === types_js_1.VulnerabilityType.SQL_INJECTION);
                if (alreadyFound) {
                    continue;
                }
                const finding = {
                    id: (0, uuid_js_1.v4)(),
                    type: types_js_1.VulnerabilityType.SQL_INJECTION,
                    severity: types_js_1.Severity.HIGH,
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
                };
                findings.push(finding);
            }
        }
        return findings;
    }
    /**
     * Simple heuristic: skip lines that appear to be comments.
     */
    isCommentedOut(line, languageId) {
        const trimmed = line.trim();
        if (languageId === 'python' || languageId === 'ruby') {
            return trimmed.startsWith('#');
        }
        return (trimmed.startsWith('//') ||
            trimmed.startsWith('*') ||
            trimmed.startsWith('/*') ||
            trimmed.startsWith('<!--'));
    }
}
exports.SqlInjectionRule = SqlInjectionRule;
//# sourceMappingURL=sqlInjectionRule.js.map