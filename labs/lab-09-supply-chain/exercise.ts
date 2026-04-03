import { createTestRunner } from '../test-utils.js';
const { test, assert, assertEqual, assertDeepEqual, summary } = createTestRunner('Lab 09 — Sécurité de la Supply Chain');

// ============================================================================
// Types
// ============================================================================

interface SemverParsed {
  major: number;
  minor: number;
  patch: number;
}

interface Vulnerability {
  package: string;
  range: string;
  severity: string;
}

interface AuditResult {
  package: string;
  severity: string;
  installedVersion: string;
}

interface RiskScore {
  score: number;
  level: string;
}

// ============================================================================
// Fonctions à implémenter
// ============================================================================

/**
 * Parse une version sémantique "MAJOR.MINOR.PATCH".
 * Retourne null si le format est invalide.
 */
function parseSemver(version: string): SemverParsed | null {
  // TODO: Implémenter le parsing semver
  return null;
}

/**
 * Vérifie si une version est dans une plage vulnérable.
 * Format de la plage : ">=1.0.0 <1.2.3"
 * Comparaison : major, puis minor, puis patch.
 */
function isVulnerableRange(version: string, range: string): boolean {
  // TODO: Implémenter la vérification de plage
  return false;
}

/**
 * Détecte les tentatives de typosquatting.
 * Retourne les packages connus dont la distance d'édition (Levenshtein) est 1 ou 2 par rapport au nom donné.
 */
function detectTyposquat(packageName: string, knownPackages: string[]): string[] {
  // TODO: Implémenter la détection de typosquatting
  return [];
}

/**
 * Audite les dépendances contre une liste de vulnérabilités connues.
 * Pour chaque dépendance, vérifie si sa version est dans une plage vulnérable.
 */
function auditDependencies(
  deps: Record<string, string>,
  vulnerabilities: Vulnerability[]
): AuditResult[] {
  // TODO: Implémenter l'audit des dépendances
  return [];
}

/**
 * Calcule un score de risque à partir des vulnérabilités trouvées.
 * Points : critical=10, high=7, medium=4, low=1.
 * Niveaux : score < 10 → 'low', < 25 → 'medium', < 50 → 'high', >= 50 → 'critical'.
 */
function calculateRiskScore(deps: Array<{ package: string; severity: string }>): RiskScore {
  // TODO: Implémenter le calcul de score
  return { score: 0, level: 'low' };
}

// ============================================================================
// Tests
// ============================================================================

await test('parseSemver — parse une version valide', async () => {
  assertDeepEqual(parseSemver('1.2.3'), { major: 1, minor: 2, patch: 3 });
  assertDeepEqual(parseSemver('0.0.1'), { major: 0, minor: 0, patch: 1 });
});

await test('parseSemver — retourne null pour un format invalide', async () => {
  assertEqual(parseSemver('1.2'), null);
  assertEqual(parseSemver('abc'), null);
  assertEqual(parseSemver(''), null);
});

await test('isVulnerableRange — détecte une version vulnérable', async () => {
  assert(isVulnerableRange('1.1.0', '>=1.0.0 <1.2.0'));
  assert(isVulnerableRange('1.0.0', '>=1.0.0 <1.2.0'));
  assert(!isVulnerableRange('1.2.0', '>=1.0.0 <1.2.0'));
  assert(!isVulnerableRange('0.9.9', '>=1.0.0 <1.2.0'));
});

await test('detectTyposquat — trouve les noms similaires', async () => {
  const known = ['express', 'lodash', 'react', 'axios'];
  const result = detectTyposquat('expres', known);
  assert(result.includes('express'));
});

await test('detectTyposquat — aucun résultat si le nom est exact', async () => {
  const known = ['express', 'lodash'];
  const result = detectTyposquat('express', known);
  assertEqual(result.length, 0);
});

await test('auditDependencies — identifie les dépendances vulnérables', async () => {
  const deps = { 'lodash': '4.17.15', 'express': '4.18.0' };
  const vulns: Vulnerability[] = [
    { package: 'lodash', range: '>=4.0.0 <4.17.21', severity: 'high' }
  ];
  const result = auditDependencies(deps, vulns);
  assertEqual(result.length, 1);
  assertEqual(result[0].package, 'lodash');
  assertEqual(result[0].severity, 'high');
});

await test('calculateRiskScore — calcule le score correctement', async () => {
  const result = calculateRiskScore([
    { package: 'a', severity: 'critical' },
    { package: 'b', severity: 'high' }
  ]);
  assertEqual(result.score, 17);
  assertEqual(result.level, 'medium');
});

await test('calculateRiskScore — niveau low pour un score faible', async () => {
  const result = calculateRiskScore([
    { package: 'a', severity: 'low' },
    { package: 'b', severity: 'low' }
  ]);
  assertEqual(result.score, 2);
  assertEqual(result.level, 'low');
});

summary();
