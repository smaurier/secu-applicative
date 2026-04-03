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
// Implémentations
// ============================================================================

function parseSemver(version: string): SemverParsed | null {
  const match = version.match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!match) return null;
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
  };
}

function compareSemver(a: SemverParsed, b: SemverParsed): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

function isVulnerableRange(version: string, range: string): boolean {
  const parsed = parseSemver(version);
  if (!parsed) return false;

  const parts = range.split(' ');
  let gte: SemverParsed | null = null;
  let lt: SemverParsed | null = null;

  for (const part of parts) {
    if (part.startsWith('>=')) {
      gte = parseSemver(part.slice(2));
    } else if (part.startsWith('<')) {
      lt = parseSemver(part.slice(1));
    }
  }

  if (gte && compareSemver(parsed, gte) < 0) return false;
  if (lt && compareSemver(parsed, lt) >= 0) return false;

  return true;
}

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }

  return dp[m][n];
}

function detectTyposquat(packageName: string, knownPackages: string[]): string[] {
  return knownPackages.filter(known => {
    if (known === packageName) return false;
    const dist = levenshtein(packageName, known);
    return dist >= 1 && dist <= 2;
  });
}

function auditDependencies(
  deps: Record<string, string>,
  vulnerabilities: Vulnerability[]
): AuditResult[] {
  const results: AuditResult[] = [];

  for (const [pkg, version] of Object.entries(deps)) {
    for (const vuln of vulnerabilities) {
      if (vuln.package === pkg && isVulnerableRange(version, vuln.range)) {
        results.push({
          package: pkg,
          severity: vuln.severity,
          installedVersion: version,
        });
      }
    }
  }

  return results;
}

function calculateRiskScore(deps: Array<{ package: string; severity: string }>): RiskScore {
  const severityPoints: Record<string, number> = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 1,
  };

  const score = deps.reduce((sum, d) => sum + (severityPoints[d.severity] ?? 0), 0);

  let level: string;
  if (score < 10) level = 'low';
  else if (score < 25) level = 'medium';
  else if (score < 50) level = 'high';
  else level = 'critical';

  return { score, level };
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
