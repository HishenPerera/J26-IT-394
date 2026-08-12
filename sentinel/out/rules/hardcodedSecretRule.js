"use strict";
/**
 * Sentinel — Hardcoded Secrets Rule
 *
 * Detects API keys, passwords, tokens, and other credentials
 * hardcoded directly in source code.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.HardcodedSecretRule = void 0;
const uuid_js_1 = require("../util/uuid.js");
const types_js_1 = require("../analyzer/types.js");
const SECRET_PATTERNS = [
    // Generic API key assignment
    {
        regex: /(?:api_?key|apikey|api_?token)\s*[=:]\s*["'`][A-Za-z0-9\-_]{16,}["'`]/gi,
        confidence: 0.90,
        message: 'Hardcoded API key detected. Store secrets in environment variables or a secrets manager.',
    },
    // Password assignments
    {
        regex: /(?:password|passwd|pwd|secret)\s*[=:]\s*["'`][^"'`\s]{6,}["'`]/gi,
        confidence: 0.85,
        message: 'Hardcoded password detected. Never commit credentials to source control.',
    },
    // AWS Access Key ID pattern
    {
        regex: /AKIA[0-9A-Z]{16}/g,
        confidence: 0.98,
        message: 'AWS Access Key ID pattern detected. This is an active credential — rotate immediately.',
    },
    // AWS Secret Access Key
    {
        regex: /(?:aws_secret|aws_access)\s*[=:]\s*["'`][A-Za-z0-9/+=]{40}["'`]/gi,
        confidence: 0.95,
        message: 'AWS Secret Access Key pattern detected. Rotate immediately and use IAM roles.',
    },
    // JWT / Bearer token
    {
        regex: /(?:token|bearer|jwt)\s*[=:]\s*["'`]eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+["'`]/gi,
        confidence: 0.95,
        message: 'Hardcoded JWT token detected. Tokens should never be embedded in source code.',
    },
    // Private key header
    {
        regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
        confidence: 0.99,
        message: 'Private key embedded in source code. Remove immediately — this is a critical security risk.',
    },
    // OpenAI / Anthropic / common AI API keys
    {
        regex: /["'`](?:sk-|sk-ant-|AIza)[A-Za-z0-9\-_]{20,}["'`]/g,
        confidence: 0.97,
        message: 'AI service API key (OpenAI/Anthropic/Google) detected in source code.',
    },
    // GitHub Personal Access Token
    {
        regex: /(?:github|gh)_?(?:token|pat)\s*[=:]\s*["'`](?:ghp_|github_pat_)[A-Za-z0-9_]{20,}["'`]/gi,
        confidence: 0.97,
        message: 'GitHub Personal Access Token detected. Revoke and use GitHub Actions secrets.',
    },
    // Connection strings with credentials
    {
        regex: /(?:connection_?string|conn_?str)\s*[=:]\s*["'`][^"'`]*(?:password|pwd)=[^;@"'`\s]+/gi,
        confidence: 0.88,
        message: 'Database connection string with embedded password detected.',
    },
    // Generic "secret" variable with long string value
    {
        regex: /(?:const|let|var|private|public|string)\s+\w*(?:secret|key|token|cred)\w*\s*[=:]\s*["'`][A-Za-z0-9\-_+/=]{20,}["'`]/gi,
        confidence: 0.75,
        message: 'Variable name suggests a secret with a hardcoded value.',
    },
];
const SUPPORTED_LANGUAGES = [
    'javascript',
    'typescript',
    'javascriptreact',
    'typescriptreact',
    'python',
    'csharp',
    'java',
    'go',
    'ruby',
    'php',
    'yaml',
    'json',
    'plaintext',
];
class HardcodedSecretRule {
    constructor() {
        this.ruleId = 'SENTINEL-SECRET-001';
        this.ruleName = 'Hardcoded Secret Detector';
        this.vulnerabilityType = types_js_1.VulnerabilityType.HARDCODED_SECRET;
        this.supportedLanguages = SUPPORTED_LANGUAGES;
    }
    analyze(text, fileName, languageId) {
        if (!this.supportedLanguages.includes(languageId)) {
            return [];
        }
        const findings = [];
        const lines = text.split('\n');
        const now = new Date().toISOString();
        for (const pattern of SECRET_PATTERNS) {
            pattern.regex.lastIndex = 0;
            let match;
            while ((match = pattern.regex.exec(text)) !== null) {
                const beforeMatch = text.substring(0, match.index);
                const lineNumber = beforeMatch.split('\n').length;
                const lastNewline = beforeMatch.lastIndexOf('\n');
                const columnNumber = match.index - (lastNewline === -1 ? 0 : lastNewline + 1);
                const lineContent = lines[lineNumber - 1] || '';
                // Skip commented-out lines
                const trimmed = lineContent.trim();
                if (trimmed.startsWith('//') ||
                    trimmed.startsWith('#') ||
                    trimmed.startsWith('*') ||
                    trimmed.startsWith('<!--')) {
                    continue;
                }
                // Skip placeholder/example values
                if (this.isPlaceholder(match[0])) {
                    continue;
                }
                const alreadyFound = findings.some(f => f.lineNumber === lineNumber && f.type === types_js_1.VulnerabilityType.HARDCODED_SECRET);
                if (alreadyFound) {
                    continue;
                }
                // Redact actual value in codeSnippet for safety
                const safeSnippet = lineContent.trim().replace(/["'`][A-Za-z0-9\-_+/=]{6,}["'`]/g, '"[REDACTED]"');
                findings.push({
                    id: (0, uuid_js_1.v4)(),
                    type: types_js_1.VulnerabilityType.HARDCODED_SECRET,
                    severity: types_js_1.Severity.CRITICAL,
                    confidence: pattern.confidence,
                    message: pattern.message,
                    fileName,
                    lineNumber,
                    columnNumber,
                    codeSnippet: safeSnippet,
                    detectedAt: now,
                    detectedByRule: this.ruleId,
                    rangeStart: match.index,
                    rangeEnd: match.index + match[0].length,
                });
            }
        }
        return findings;
    }
    /**
     * Returns true only if the matched value is clearly a developer placeholder,
     * not a real credential.
     *
     * ⚠️  Be conservative — false negatives (missed detections) are worse than
     *     false positives here. Only skip values that are obviously fake.
     *
     * NOTE: Do NOT filter 'example' as a substring — real AWS keys like
     *       AKIAIOSFODNN7EXAMPLE contain the word 'EXAMPLE' and must still be flagged.
     */
    isPlaceholder(value) {
        const lower = value.toLowerCase();
        // Only match clearly-intended placeholder phrases
        const fullPhrases = [
            'your_api_key',
            'your-api-key',
            'your_secret',
            'your-secret',
            'your_token',
            'your-token',
            'replace_me',
            'replace-me',
            'insert_here',
            'insert-here',
            'changeme',
            'change_me',
            'placeholder',
            'enter_your',
            'enter-your',
            'add_your',
            '<your',
            '[your',
            '{your',
        ];
        if (fullPhrases.some(p => lower.includes(p))) {
            return true;
        }
        // Repeated single character (xxxxxx, 000000, aaaaaa) — obviously fake
        if (/^(.)\1{5,}$/.test(value)) {
            return true;
        }
        // More than 4 consecutive x’s or *’s — placeholder masking pattern
        if (/x{5,}|X{5,}|\*{4,}|\.{4,}/i.test(value)) {
            return true;
        }
        return false;
    }
}
exports.HardcodedSecretRule = HardcodedSecretRule;
//# sourceMappingURL=hardcodedSecretRule.js.map