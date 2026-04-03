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
// Fonctions à implémenter
// ============================================================================

/**
 * Classifie une vulnérabilité selon sa description.
 * Retourne la catégorie OWASP (A01-A10) basée sur des mots-clés :
 * - "access control", "privilege", "IDOR" → "A01"
 * - "crypto", "hash", "password storage" → "A02"
 * - "injection", "SQL", "XSS", "command" → "A03"
 * - "design", "threat model" → "A04"
 * - "misconfiguration", "default", "debug mode" → "A05"
 * - "outdated", "vulnerable component", "dependency" → "A06"
 * - "authentication", "brute force", "session" → "A07"
 * - "integrity", "deserialization", "CI/CD" → "A08"
 * - "logging", "monitoring", "audit" → "A09"
 * - "SSRF", "server-side request" → "A10"
 * Retourne "unknown" si aucune catégorie ne correspond.
 */
function classifyVulnerability(description: string): string {
  // TODO: Implémenter la classification basée sur les mots-clés
  return 'unknown';
}

/**
 * Évalue le score de risque d'une vulnérabilité.
 * Formule : severityWeight * (exploitability + impact) / 2
 * Poids de sévérité : critical=4, high=3, medium=2, low=1
 * Retourne le résultat arrondi à 1 décimale.
 */
function assessRisk(severity: string, exploitability: number, impact: number): number {
  // TODO: Calculer le score de risque
  return 0;
}

/**
 * Priorise les vulnérabilités.
 * Trie par sévérité (critical d'abord), puis par catégorie (A01 d'abord).
 */
function prioritizeVulnerabilities(vulns: Vulnerability[]): Vulnerability[] {
  // TODO: Trier les vulnérabilités par priorité
  return [];
}

/**
 * Détecte les patterns d'injection SQL dans une requête.
 * Vérifie la présence de : ' OR ', '--', '; DROP', 'UNION SELECT', '1=1'
 */
function detectSQLInjection(query: string): boolean {
  // TODO: Détecter les patterns d'injection SQL
  return false;
}

/**
 * Génère un rapport synthétique des vulnérabilités.
 * Format : "X vulnérabilités trouvées : Y critical, Z high, W medium, V low"
 * (n'affiche que les sévérités présentes)
 */
function generateReport(vulns: Vulnerability[]): string {
  // TODO: Générer le rapport
  return '';
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
