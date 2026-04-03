import { createTestRunner } from '../test-utils.js';
const { test, assert, assertEqual, assertIncludes, summary } = createTestRunner('Lab 01 — OWASP Top 10');

// ============================================================================
// Types
// ============================================================================

interface Vulnerability {
  id: string;
  description: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  recommendation: string;
}

// ============================================================================
// Implémentations
// ============================================================================

function classifyVulnerability(description: string): string {
  const lower = description.toLowerCase();

  const categories: [string, string[]][] = [
    ['A01', ['access control', 'privilege', 'idor']],
    ['A02', ['crypto', 'hash', 'password storage']],
    ['A03', ['injection', 'sql', 'xss', 'command']],
    ['A04', ['design', 'threat model']],
    ['A05', ['misconfiguration', 'default', 'debug mode']],
    ['A06', ['outdated', 'vulnerable component', 'dependency']],
    ['A07', ['authentication', 'brute force', 'session']],
    ['A08', ['integrity', 'deserialization', 'ci/cd']],
    ['A09', ['logging', 'monitoring', 'audit']],
    ['A10', ['ssrf', 'server-side request']],
  ];

  for (const [category, keywords] of categories) {
    if (keywords.some((kw) => lower.includes(kw))) {
      return category;
    }
  }

  return 'unknown';
}

function assessRisk(severity: string, exploitability: number, impact: number): number {
  const weights: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  };
  const weight = weights[severity] ?? 1;
  const score = (weight * (exploitability + impact)) / 2;
  return Math.round(score * 10) / 10;
}

function prioritizeVulnerabilities(vulns: Vulnerability[]): Vulnerability[] {
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };

  return [...vulns].sort((a, b) => {
    const sevDiff = (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4);
    if (sevDiff !== 0) return sevDiff;
    return a.category.localeCompare(b.category);
  });
}

function detectSQLInjection(query: string): boolean {
  const upper = query.toUpperCase();
  const patterns = ["' OR ", '--', '; DROP', 'UNION SELECT', '1=1'];
  return patterns.some((p) => upper.includes(p.toUpperCase()));
}

function generateReport(vulns: Vulnerability[]): string {
  const counts: Record<string, number> = {};
  for (const v of vulns) {
    counts[v.severity] = (counts[v.severity] ?? 0) + 1;
  }

  const parts: string[] = [];
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    if (counts[sev]) {
      parts.push(`${counts[sev]} ${sev}`);
    }
  }

  return `${vulns.length} vulnérabilités trouvées : ${parts.join(', ')}`;
}

// ============================================================================
// Tests
// ============================================================================

await test('classifyVulnerability — détecte A01 (Broken Access Control)', async () => {
  assertEqual(classifyVulnerability('Broken access control on admin panel'), 'A01');
  assertEqual(classifyVulnerability('IDOR vulnerability found'), 'A01');
});

await test('classifyVulnerability — détecte A03 (Injection)', async () => {
  assertEqual(classifyVulnerability('SQL injection in login form'), 'A03');
  assertEqual(classifyVulnerability('XSS reflected in search'), 'A03');
});

await test('classifyVulnerability — retourne unknown pour description inconnue', async () => {
  assertEqual(classifyVulnerability('random text without keywords'), 'unknown');
});

await test('assessRisk — calcul correct du score', async () => {
  assertEqual(assessRisk('critical', 8, 9), 34);
  assertEqual(assessRisk('low', 3, 5), 4);
  assertEqual(assessRisk('medium', 7, 3), 10);
});

await test('prioritizeVulnerabilities — tri par sévérité puis catégorie', async () => {
  const vulns: Vulnerability[] = [
    { id: '1', description: 'Test', category: 'A03', severity: 'high', recommendation: 'Fix' },
    { id: '2', description: 'Test', category: 'A01', severity: 'critical', recommendation: 'Fix' },
    { id: '3', description: 'Test', category: 'A05', severity: 'critical', recommendation: 'Fix' },
  ];
  const sorted = prioritizeVulnerabilities(vulns);
  assertEqual(sorted[0].id, '2');
  assertEqual(sorted[1].id, '3');
  assertEqual(sorted[2].id, '1');
});

await test('detectSQLInjection — détecte les injections', async () => {
  assert(detectSQLInjection("admin' OR '1'='1"), 'Devrait détecter OR injection');
  assert(detectSQLInjection('DROP TABLE users; --'), 'Devrait détecter les commentaires SQL');
  assert(detectSQLInjection('1 UNION SELECT * FROM passwords'), 'Devrait détecter UNION SELECT');
});

await test('detectSQLInjection — accepte les requêtes légitimes', async () => {
  assert(!detectSQLInjection('SELECT * FROM users WHERE id = 1'), 'Requête légitime');
  assert(!detectSQLInjection('John Doe'), 'Texte simple');
});

await test('generateReport — format correct', async () => {
  const vulns: Vulnerability[] = [
    { id: '1', description: 'Test', category: 'A01', severity: 'critical', recommendation: 'Fix' },
    { id: '2', description: 'Test', category: 'A03', severity: 'high', recommendation: 'Fix' },
    { id: '3', description: 'Test', category: 'A05', severity: 'medium', recommendation: 'Fix' },
  ];
  const report = generateReport(vulns);
  assertIncludes(report, '3 vulnérabilités trouvées');
  assertIncludes(report, '1 critical');
  assertIncludes(report, '1 high');
  assertIncludes(report, '1 medium');
});

summary();
