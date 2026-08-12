"use strict";
/**
 * Sentinel — Security Finding Types
 * This is the TEAM CONTRACT between Component 1 (Sentinel) and Component 2 (Behaviour Tracker).
 * Do NOT change field names without coordinating with Member 2.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.DeveloperAction = exports.VulnerabilityType = exports.Severity = void 0;
// ─── Severity ────────────────────────────────────────────────────────────────
var Severity;
(function (Severity) {
    Severity["CRITICAL"] = "CRITICAL";
    Severity["HIGH"] = "HIGH";
    Severity["MEDIUM"] = "MEDIUM";
    Severity["LOW"] = "LOW";
    Severity["INFO"] = "INFO";
})(Severity || (exports.Severity = Severity = {}));
// ─── Vulnerability Types ──────────────────────────────────────────────────────
var VulnerabilityType;
(function (VulnerabilityType) {
    VulnerabilityType["SQL_INJECTION"] = "SQL_INJECTION";
    VulnerabilityType["XSS"] = "XSS";
    VulnerabilityType["HARDCODED_SECRET"] = "HARDCODED_SECRET";
    VulnerabilityType["COMMAND_INJECTION"] = "COMMAND_INJECTION";
    VulnerabilityType["PATH_TRAVERSAL"] = "PATH_TRAVERSAL";
    VulnerabilityType["MISSING_INPUT_VALIDATION"] = "MISSING_INPUT_VALIDATION";
    VulnerabilityType["UNSAFE_DESERIALIZATION"] = "UNSAFE_DESERIALIZATION";
    VulnerabilityType["WEAK_CRYPTOGRAPHY"] = "WEAK_CRYPTOGRAPHY";
    VulnerabilityType["INSECURE_AUTH"] = "INSECURE_AUTH";
    VulnerabilityType["SENSITIVE_DATA_EXPOSURE"] = "SENSITIVE_DATA_EXPOSURE";
})(VulnerabilityType || (exports.VulnerabilityType = VulnerabilityType = {}));
// ─── Developer Actions (behaviour events) ────────────────────────────────────
var DeveloperAction;
(function (DeveloperAction) {
    DeveloperAction["DETECTED"] = "DETECTED";
    DeveloperAction["WARNING_SHOWN"] = "WARNING_SHOWN";
    DeveloperAction["EXPLANATION_VIEWED"] = "EXPLANATION_VIEWED";
    DeveloperAction["SECURE_EXAMPLE_VIEWED"] = "SECURE_EXAMPLE_VIEWED";
    DeveloperAction["FIX_APPLIED"] = "FIX_APPLIED";
    DeveloperAction["IGNORED"] = "IGNORED";
    DeveloperAction["MARKED_FALSE_POSITIVE"] = "MARKED_FALSE_POSITIVE";
    DeveloperAction["DISMISSED"] = "DISMISSED";
    DeveloperAction["FIXED"] = "FIXED";
})(DeveloperAction || (exports.DeveloperAction = DeveloperAction = {}));
//# sourceMappingURL=types.js.map