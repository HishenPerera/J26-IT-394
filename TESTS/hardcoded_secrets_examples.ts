/**
 * ============================================================
 *  HARDCODED SECRET VULNERABILITY EXAMPLES — Sentinel Test File
 *  Rule: SENTINEL-SECRET-001 | Severity: CRITICAL
 * ============================================================
 *
 *  Open this file in VS Code with the Sentinel extension active.
 *  Every marked line below will be underlined in RED with a
 *  CRITICAL diagnostic. Values are fake but match real patterns.
 * ============================================================
 */

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  1. GENERIC API KEYS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ── api_key / apikey / api_token assignments ─────────────────────────────────

const api_key = "xK9mP2nRqW7vB4sL8dF3jH6tY1cA5eG0";          // ❌ CRITICAL — 90% confidence
const apikey  = "zN5wQ8uE2rT6yI0oP3aS7dF1gH4jK9lM";          // ❌ CRITICAL — 90% confidence
const api_token = `mB3nV6xC9kL2pR5sW8tY1aE4qU7iO0zG`;        // ❌ CRITICAL — 90% confidence

const config = {
  apiKey: "hJ5mK8nP2qR7tW4xL9sB3vF6yA1eG0cD",               // ❌ CRITICAL — 90% confidence
};


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  2. PASSWORDS & SECRETS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const password = "SuperSecr3t!Pass#2024";                      // ❌ CRITICAL — 85% confidence
const passwd   = "C0rr3ctH0rseBatt3ryStaple";                  // ❌ CRITICAL — 85% confidence
const pwd      = "P@ssw0rdABC123secure";                       // ❌ CRITICAL — 85% confidence
const secret   = "my-ultra-secret-value-do-not-share";         // ❌ CRITICAL — 85% confidence

const dbConfig = {
  password: "Pr0ductionP@ss!2024",                             // ❌ CRITICAL — 85% confidence
  secret:   "jwt-signing-secret-AbCdEfGhIjKlMn",              // ❌ CRITICAL — 85% confidence
};


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  3. AWS CREDENTIALS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ── AWS Access Key ID (unique AKIA prefix — 98% confidence) ─────────────────
const awsAccessKeyId = "AKIAIOSFODNN7EXAMPLE";                 // ❌ CRITICAL — 98% confidence
const AWS_KEY        = "AKIAJ3EXAMPLE2XAMPLEKEY3";             // ❌ CRITICAL — 98% confidence

// ── AWS Secret Access Key ────────────────────────────────────────────────────
const aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";  // ❌ CRITICAL — 95% confidence
const aws_access = "Je7MtGbClwBF/2Sk9EXAMPLE/gfiS+Extended==";    // ❌ CRITICAL — 95% confidence


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  4. JWT / BEARER TOKENS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// All real JWTs start with eyJ (base64-encoded '{"')
const token  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36P";  // ❌ CRITICAL — 95% confidence
const bearer = "eyJhbGciOiJSUzI1NiJ9.eyJ1c2VySWQiOiI0MiJ9.dummySignatureValueForDemoOnly";                         // ❌ CRITICAL — 95% confidence
const jwt    = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.exampleSignatureHereForSentinel";      // ❌ CRITICAL — 95% confidence


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  5. PRIVATE KEYS EMBEDDED IN SOURCE
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// 99% confidence — the most dangerous pattern
const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29jNiTSXFDKxA
s7GGDcMPprEasHJDon7RXfBMuBJCMHPPMJF5r1lMikNuRkMNLkMbCpH5uTBcCcq
-----END RSA PRIVATE KEY-----
`;                                                              // ❌ CRITICAL — 99% confidence

const sshKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHQvFJqLEMWWWAaU1SENTINELTESTKEY12345678==
-----END PRIVATE KEY-----`;                                    // ❌ CRITICAL — 99% confidence


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  6. AI SERVICE API KEYS (OpenAI / Anthropic / Google)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const openaiKey    = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABCDEF";   // ❌ CRITICAL — 97%
const anthropicKey = "sk-ant-api03-ExampleAnthropicKeyABCDEFGHIJKLMN";       // ❌ CRITICAL — 97%
const googleKey    = "AIzaSyDExampleGoogleAPIKeyForSentinelDemo123456";       // ❌ CRITICAL — 97%


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  7. GITHUB PERSONAL ACCESS TOKEN (PAT)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const github_token = "ghp_ExampleGitHubTokenSentinelDemoABCDEF1234";         // ❌ CRITICAL — 97%
const gh_pat       = "github_pat_ExamplePatTokenSentinel1234567890ABCDE";    // ❌ CRITICAL — 97%


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  8. DATABASE CONNECTION STRING WITH CREDENTIALS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const connection_string = "Server=prod.db.internal;Database=AppDB;User=admin;password=Pr0d!Secret2024;";  // ❌ CRITICAL — 88%
const conn_str = "mongodb+srv://admin:Sup3rS3cr3tPassDB@cluster0.mongodb.net/myapp";                      // ❌ CRITICAL — 88%


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  9. GENERIC SECRET / KEY VARIABLE NAMES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const encryptionKey = "AbCdEfGhIjKlMnOpQrStUvWxYz123456";     // ❌ CRITICAL — 75% confidence
const sessionToken  = "UsErSeSSiOnToKeN-ABCDEFGHIJKLM-2024";  // ❌ CRITICAL — 75% confidence
const authSecret    = "auth-secret-signing-key-prod-v2-2024";  // ❌ CRITICAL — 75% confidence
private signingKey  = "HmacSHA256-prod-signing-AbCdEfGhIjKl";  // ❌ CRITICAL — 75% confidence


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  ✅ SAFE PATTERNS (Sentinel will NOT flag these)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ✅ Read from environment variables — the correct approach
const safeApiKey    = process.env.API_KEY;
const safePassword  = process.env.DB_PASSWORD;
const safeJwt       = process.env.JWT_SECRET;
const safeAwsKey    = process.env.AWS_ACCESS_KEY_ID;
const safeAwsSecret = process.env.AWS_SECRET_ACCESS_KEY;

// ✅ Using a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault)
// const secret = await secretsManager.getSecretValue({ SecretId: 'prod/myapp/db' });

// ✅ Placeholder value — Sentinel recognises these as non-real and skips them
const devApiKey = "your_api_key_here";       // skipped (placeholder phrase)
const devSecret = "replace_me";              // skipped (placeholder phrase)
