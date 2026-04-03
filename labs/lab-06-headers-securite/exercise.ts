import { createTestRunner } from '../test-utils.js';
const { test, assert, assertEqual, assertDeepEqual, summary } = createTestRunner('Lab 06 — En-têtes HTTP de Sécurité');

// ============================================================================
// Types
// ============================================================================

interface SecurityHeaders {
  'Content-Security-Policy'?: string;
  'Strict-Transport-Security'?: string;
  'X-Content-Type-Options'?: string;
  'X-Frame-Options'?: string;
  'Referrer-Policy'?: string;
  'Permissions-Policy'?: string;
  [key: string]: string | undefined;
}

interface CSPDirective {
  name: string;
  values: string[];
}

interface HeaderAuditResult {
  present: string[];
  missing: string[];
  score: number;
}

// ============================================================================
// Fonctions à implémenter
// ============================================================================

/**
 * Parse une chaîne CSP en tableau de directives.
 * Ex: "default-src 'self'; script-src 'self' cdn.example.com"
 * → [{ name: 'default-src', values: ["'self'"] }, { name: 'script-src', values: ["'self'", "cdn.example.com"] }]
 */
function parseCSP(csp: string): CSPDirective[] {
  // TODO: Implémenter le parsing CSP
  return [];
}

/**
 * Reconstruit une chaîne CSP depuis un tableau de directives.
 * Inverse de parseCSP, les directives sont jointes par '; '.
 */
function buildCSP(directives: CSPDirective[]): string {
  // TODO: Implémenter la construction CSP
  return '';
}

/**
 * Audite les en-têtes de sécurité présents.
 * En-têtes requis : Content-Security-Policy, Strict-Transport-Security,
 * X-Content-Type-Options, X-Frame-Options, Referrer-Policy.
 * score = (present.length / 5) * 100
 */
function auditHeaders(headers: SecurityHeaders): HeaderAuditResult {
  // TODO: Implémenter l'audit des en-têtes
  return { present: [], missing: [], score: 0 };
}

/**
 * Construit un en-tête HSTS.
 * Ex: buildHSTS(31536000, true, true) → "max-age=31536000; includeSubDomains; preload"
 */
function buildHSTS(maxAge: number, includeSubDomains: boolean, preload: boolean): string {
  // TODO: Implémenter la construction HSTS
  return '';
}

/**
 * Vérifie si une CSP est sécurisée.
 * Patterns dangereux dans script-src : 'unsafe-inline', 'unsafe-eval', '*'
 * Retourne { safe: boolean, warnings: string[] }
 */
function isCSPSafe(csp: string): { safe: boolean; warnings: string[] } {
  // TODO: Implémenter la vérification de sécurité CSP
  return { safe: true, warnings: [] };
}

// ============================================================================
// Tests
// ============================================================================

await test('parseCSP — parse les directives CSP', async () => {
  const result = parseCSP("default-src 'self'; script-src 'self' cdn.example.com; style-src 'self' 'unsafe-inline'");
  assertEqual(result.length, 3);
  assertEqual(result[0].name, 'default-src');
  assertDeepEqual(result[0].values, ["'self'"]);
  assertEqual(result[1].name, 'script-src');
  assertDeepEqual(result[1].values, ["'self'", "cdn.example.com"]);
});

await test('buildCSP — reconstruit une chaîne CSP', async () => {
  const directives = [
    { name: 'default-src', values: ["'self'"] },
    { name: 'script-src', values: ["'self'", "cdn.example.com"] }
  ];
  assertEqual(buildCSP(directives), "default-src 'self'; script-src 'self' cdn.example.com");
});

await test('auditHeaders — identifie les en-têtes manquants', async () => {
  const result = auditHeaders({
    'Content-Security-Policy': "default-src 'self'",
    'Strict-Transport-Security': 'max-age=31536000',
    'X-Content-Type-Options': 'nosniff'
  });
  assertEqual(result.present.length, 3);
  assertEqual(result.missing.length, 2);
  assertEqual(result.score, 60);
});

await test('auditHeaders — score parfait avec tous les en-têtes', async () => {
  const result = auditHeaders({
    'Content-Security-Policy': "default-src 'self'",
    'Strict-Transport-Security': 'max-age=31536000',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  });
  assertEqual(result.score, 100);
});

await test('buildHSTS — construit un en-tête HSTS complet', async () => {
  assertEqual(buildHSTS(31536000, true, true), 'max-age=31536000; includeSubDomains; preload');
  assertEqual(buildHSTS(86400, false, false), 'max-age=86400');
});

await test('buildHSTS — options partielles', async () => {
  assertEqual(buildHSTS(31536000, true, false), 'max-age=31536000; includeSubDomains');
  assertEqual(buildHSTS(31536000, false, true), 'max-age=31536000; preload');
});

await test('isCSPSafe — détecte les patterns dangereux', async () => {
  const result = isCSPSafe("default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'");
  assert(!result.safe);
  assertEqual(result.warnings.length, 2);
});

await test('isCSPSafe — valide une CSP sécurisée', async () => {
  const result = isCSPSafe("default-src 'self'; script-src 'self' cdn.example.com");
  assert(result.safe);
  assertEqual(result.warnings.length, 0);
});

summary();
