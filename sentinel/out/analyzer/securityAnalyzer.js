"use strict";
/**
 * Sentinel — Security Analyzer
 *
 * Orchestrates all security rules. This is the main analysis engine called
 * by the VS Code extension whenever the document changes.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityAnalyzer = void 0;
const sqlInjectionRule_js_1 = require("../rules/sqlInjectionRule.js");
const xssRule_js_1 = require("../rules/xssRule.js");
const hardcodedSecretRule_js_1 = require("../rules/hardcodedSecretRule.js");
class SecurityAnalyzer {
    constructor() {
        // Register all detection rules here.
        // To add a new rule: create the class, import it, and add it to this list.
        this.rules = [
            new sqlInjectionRule_js_1.SqlInjectionRule(),
            new xssRule_js_1.XssRule(),
            new hardcodedSecretRule_js_1.HardcodedSecretRule(),
        ];
    }
    /**
     * Analyze a document and return all security findings.
     *
     * @param text - Full document text content
     * @param fileName - Absolute path to the file
     * @param languageId - VS Code language identifier (e.g. 'csharp', 'javascript')
     * @returns Array of SecurityFinding objects (may be empty if no issues found)
     */
    analyze(text, fileName, languageId) {
        const allFindings = [];
        for (const rule of this.rules) {
            try {
                const findings = rule.analyze(text, fileName, languageId);
                allFindings.push(...findings);
            }
            catch (err) {
                // Never let a single rule crash the whole analysis
                console.error(`[Sentinel] Rule ${rule.ruleId} threw an error:`, err);
            }
        }
        // Sort by severity (CRITICAL first) then by line number
        return allFindings.sort((a, b) => {
            const severityOrder = {
                CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
            };
            const sA = severityOrder[a.severity] ?? 99;
            const sB = severityOrder[b.severity] ?? 99;
            if (sA !== sB) {
                return sA - sB;
            }
            return a.lineNumber - b.lineNumber;
        });
    }
    /**
     * Return the list of registered rules.
     */
    getRules() {
        return [...this.rules];
    }
    /**
     * Return summary stats for a set of findings.
     */
    summarize(findings) {
        const byType = {};
        const bySeverity = {};
        for (const f of findings) {
            byType[f.type] = (byType[f.type] || 0) + 1;
            bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
        }
        return {
            totalFindings: findings.length,
            criticalCount: bySeverity['CRITICAL'] || 0,
            highCount: bySeverity['HIGH'] || 0,
            mediumCount: bySeverity['MEDIUM'] || 0,
            lowCount: bySeverity['LOW'] || 0,
            byType,
        };
    }
}
exports.SecurityAnalyzer = SecurityAnalyzer;
//# sourceMappingURL=securityAnalyzer.js.map