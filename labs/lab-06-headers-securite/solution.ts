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
// Implémentations
// ============================================================================

function parseCSP(csp: string): CSPDirective[] {
  return csp.split(';').map(part => {
    const tokens = part.trim().split(/\s+/);
    return {
      name: tokens[0],
      values: tokens.slice(1),
    };
  });
}

function buildCSP(directives: CSPDirective[]): string {
  return directives
    .map(d => `${d.name} ${d.values.join(' ')}`)
    .join('; ');
}

function auditHeaders(headers: SecurityHeaders): HeaderAuditResult {
  const required = [
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Referrer-Policy',
  ];
  const present: string[] = [];
  const missing: string[] = [];
  for (const h of required) {
    if (headers[h] !== undefined) {
      present.push(h);
    } else {
      missing.push(h);
    }
  }
  const score = (present.length / 5) * 100;
  return { present, missing, score };
}

function buildHSTS(maxAge: number, includeSubDomains: boolean, preload: boolean): string {
  const parts = [`max-age=${maxAge}`];
  if (includeSubDomains) parts.push('includeSubDomains');
  if (preload) parts.push('preload');
  return parts.join('; ');
}

function isCSPSafe(csp: string): { safe: boolean; warnings: string[] } {
  const directives = parseCSP(csp);
  const warnings: string[] = [];
  for (const d of directives) {
    if (d.name === 'script-src') {
      if (d.values.includes("'unsafe-inline'")) {
        warnings.push("'unsafe-inline' détecté dans script-src");
      }
      if (d.values.includes("'unsafe-eval'")) {
        warnings.push("'unsafe-eval' détecté dans script-src");
      }
      if (d.values.includes('*')) {
        warnings.push("Wildcard '*' détecté dans script-src");
      }
    }
  }
  return { safe: warnings.length === 0, warnings };
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
