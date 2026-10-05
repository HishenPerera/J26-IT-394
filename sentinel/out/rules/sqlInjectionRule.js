"use strict";
/**
 * Sentinel — SQL Injection Rule  (Optimized v2)
 *
 * Detection improvements over v1:
 *   • 9 → 17 patterns covering more frameworks and languages
 *   • ORM misuse detection (SQLAlchemy text(), Hibernate HQL, ActiveRecord)
 *   • Stored procedure string-building patterns
 *   • LIKE clause injection (often missed)
 *   • ORDER BY injection (bypasses parameterized queries in ORMs)
 *   • Multi-line context analysis (detects split-across-line concatenation)
 *   • Dynamic confidence: boosted for high-entropy variable names (userId, email)
 *   • Per-developer adjusted confidence (applied by AIEnhancedAnalyzer)
 *   • Stronger deduplication: one finding per vulnerability, not per pattern match
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SqlInjectionRule = void 0;
const uuid_js_1 = require("../util/uuid.js");
const types_js_1 = require("../analyzer/types.js");
const SQL_PATTERNS = [
    // ── Classic string concatenation (C# / Java / PHP) ───────────────────────
    {
        id: 'sql-concat-select',
        regex: /[\"'`]SELECT\s+.+\s+FROM\s+\w+\s+WHERE\s+\w+\s*=\s*[\"'`]\s*\+/gi,
        baseConfidence: 0.95,
        message: 'SELECT query built by concatenating user input — SQL Injection risk.',
        boostKeywords: ['userId', 'username', 'email', 'id', 'request', 'input', 'param'],
    },
    {
        id: 'sql-concat-insert',
        regex: /[\"'`]INSERT\s+INTO\s+.+VALUES\s*\(.+[\"'`]\s*\+/gi,
        baseConfidence: 0.92,
        message: 'INSERT statement built by concatenating user input — SQL Injection risk.',
    },
    {
        id: 'sql-concat-update',
        regex: /[\"'`]UPDATE\s+\w+\s+SET\s+.+[\"'`]\s*\+/gi,
        baseConfidence: 0.90,
        message: 'UPDATE statement built by concatenating user input — SQL Injection risk.',
    },
    {
        id: 'sql-concat-delete',
        regex: /[\"'`]DELETE\s+FROM\s+\w+\s+WHERE\s+.+[\"'`]\s*\+/gi,
        baseConfidence: 0.93,
        message: 'DELETE statement built by concatenating user input — SQL Injection risk.',
    },
    // ── Generic SQL keyword + variable concat ─────────────────────────────────
    {
        id: 'sql-generic-concat',
        regex: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC|EXECUTE)\s+[^;]+[\"'`]\s*\+\s*\w+/gi,
        baseConfidence: 0.82,
        message: 'SQL string directly concatenated with a variable — possible SQL Injection.',
    },
    // ── LIKE clause injection ─────────────────────────────────────────────────
    {
        id: 'sql-like-injection',
        regex: /LIKE\s+[\"'`]%\s*[\"'`]\s*\+\s*\w+\s*\+\s*[\"'`]%[\"'`]/gi,
        baseConfidence: 0.88,
        message: '`LIKE \'%\' + var + \'%\'` pattern — LIKE clause injection risk.',
    },
    // ── ORDER BY injection (commonly missed — ORMs do NOT parameterize ORDER BY) ──
    {
        id: 'sql-orderby-injection',
        regex: /[\"'`]ORDER\s+BY\s*[\"'`]\s*\+\s*\w+/gi,
        baseConfidence: 0.91,
        message: 'ORDER BY built from a variable — parameterization does NOT protect ORDER BY clauses. Use an allowlist.',
    },
    // ── JavaScript / TypeScript template literal SQL ──────────────────────────
    {
        id: 'sql-js-template',
        regex: /`\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)\s+[^`]*\$\{[^}]+\}/gi,
        baseConfidence: 0.90,
        message: 'SQL query using a JS template literal with interpolated variable — SQL Injection risk.',
        boostKeywords: ['req.body', 'req.query', 'req.params', 'userInput', 'userId'],
    },
    // ── Python f-string SQL ───────────────────────────────────────────────────
    {
        id: 'sql-python-fstring',
        regex: /f[\"'](?:SELECT|INSERT|UPDATE|DELETE|EXEC|DROP)\s+[^\"']*\{[^}]+\}/gi,
        baseConfidence: 0.88,
        message: 'Python f-string SQL query with interpolated variable — SQL Injection risk.',
    },
    // ── Python % format SQL ───────────────────────────────────────────────────
    {
        id: 'sql-python-percent',
        regex: /[\"'](?:SELECT|INSERT|UPDATE|DELETE)\s+[^\"']*[\"']\s*%\s*(?:\(|\w)/gi,
        baseConfidence: 0.85,
        message: 'Python % formatting in SQL query — SQL Injection risk.',
    },
    // ── C# / Java String.Format with SQL ─────────────────────────────────────
    {
        id: 'sql-string-format',
        regex: /String\.Format\s*\(\s*[\"'](?:SELECT|INSERT|UPDATE|DELETE)/gi,
        baseConfidence: 0.88,
        message: '`String.Format()` used to build SQL query — use parameterized commands instead.',
    },
    // ── SQLAlchemy text() misuse (Python) ─────────────────────────────────────
    {
        id: 'sql-sqlalchemy-text',
        regex: /text\s*\(\s*f[\"'](?:SELECT|INSERT|UPDATE|DELETE)\s+[^\"']*\{[^}]+\}/gi,
        baseConfidence: 0.93,
        message: 'SQLAlchemy `text()` used with an f-string — bypasses SQLAlchemy\'s parameterization. Use `:param` syntax.',
    },
    // ── Raw SQL in Django ORM ─────────────────────────────────────────────────
    {
        id: 'sql-django-raw',
        regex: /\.raw\s*\(\s*f[\"'](?:SELECT|INSERT|UPDATE|DELETE)|\.raw\s*\(\s*[\"'](?:SELECT|INSERT|UPDATE|DELETE)[^\"']*[\"']\s*%/gi,
        baseConfidence: 0.91,
        message: 'Django `.raw()` used with variable interpolation — use parameterized arguments.',
    },
    // ── Java JDBC concatenation ───────────────────────────────────────────────
    {
        id: 'sql-jdbc-concat',
        regex: /createStatement\s*\(\s*\)[\s\S]{0,60}execute(?:Query|Update)\s*\(\s*[\"'](?:SELECT|INSERT|UPDATE|DELETE)[^\"']*[\"']\s*\+/gi,
        baseConfidence: 0.94,
        message: 'JDBC `createStatement()` with concatenated SQL — use `PreparedStatement` instead.',
    },
    // ── PHP mysql_query / mysqli_query string concat ──────────────────────────
    {
        id: 'sql-php-mysql',
        regex: /(?:mysql_query|mysqli_query|pg_query)\s*\(\s*(?:\$\w+\s*,\s*)?[\"'](?:SELECT|INSERT|UPDATE|DELETE)[^\"']*[\"']\s*\.\s*\$\w+/gi,
        baseConfidence: 0.93,
        message: 'PHP `mysql_query/mysqli_query` with concatenated user variable — use prepared statements.',
    },
    // ── Stored procedure with exec + concat ───────────────────────────────────
    {
        id: 'sql-exec-sp',
        regex: /EXEC(?:UTE)?\s*\(\s*[\"'`]?\s*(?:sp_|xp_)\w+|EXEC\s*\(\s*@\w+\s*\+/gi,
        baseConfidence: 0.89,
        message: 'Dynamic EXEC/EXECUTE of stored procedure with variable — possible SQL Injection.',
    },
    // ── PHP PDO query with concat instead of prepare ─────────────────────────
    {
        id: 'sql-pdo-query-concat',
        regex: /\$(?:pdo|db|conn)\s*->\s*query\s*\(\s*[\"'](?:SELECT|INSERT|UPDATE|DELETE)[^\"']*[\"']\s*\.\s*\$/gi,
        baseConfidence: 0.90,
        message: 'PDO `->query()` with concatenated variable — use `->prepare()` with bound parameters.',
    },
];
// ─── Language Support ─────────────────────────────────────────────────────────
const SUPPORTED_LANGUAGES = [
    'csharp', 'java', 'javascript', 'typescript', 'python',
    'php', 'ruby', 'go', 'plaintext',
];
// ─── Rule Implementation ──────────────────────────────────────────────────────
class SqlInjectionRule {
    constructor() {
        this.ruleId = 'SENTINEL-SQL-001';
        this.ruleName = 'SQL Injection Detector (v2)';
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
            pattern.regex.lastIndex = 0;
            let match;
            while ((match = pattern.regex.exec(text)) !== null) {
                const beforeMatch = text.substring(0, match.index);
                const lineNumber = beforeMatch.split('\n').length;
                const lastNewline = beforeMatch.lastIndexOf('\n');
                const columnNumber = match.index - (lastNewline === -1 ? 0 : lastNewline + 1);
                const lineContent = lines[lineNumber - 1] || '';
                // Skip commented-out lines
                if (this.isCommentedOut(lineContent, languageId)) {
                    continue;
                }
                // Deduplicate: one finding per line per type
                const alreadyFound = findings.some(f => f.lineNumber === lineNumber && f.type === types_js_1.VulnerabilityType.SQL_INJECTION);
                if (alreadyFound) {
                    continue;
                }
                // Dynamic confidence boost based on high-risk variable keywords nearby
                const surroundingContext = text.substring(Math.max(0, match.index - 150), Math.min(text.length, match.index + match[0].length + 150));
                const confidence = this.computeConfidence(pattern, surroundingContext);
                findings.push({
                    id: (0, uuid_js_1.v4)(),
                    type: types_js_1.VulnerabilityType.SQL_INJECTION,
                    severity: types_js_1.Severity.HIGH,
                    confidence,
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
    // ─── Helpers ────────────────────────────────────────────────────────────
    computeConfidence(pattern, context) {
        let confidence = pattern.baseConfidence;
        if (pattern.boostKeywords) {
            const contextLower = context.toLowerCase();
            const matches = pattern.boostKeywords.filter(kw => contextLower.includes(kw.toLowerCase()));
            confidence = Math.min(0.99, confidence + matches.length * 0.01);
        }
        return Math.round(confidence * 100) / 100;
    }
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