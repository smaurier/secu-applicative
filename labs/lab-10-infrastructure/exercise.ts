import { createTestRunner } from '../test-utils.js';
const { test, assert, assertEqual, assertDeepEqual, summary } = createTestRunner('Lab 10 — Sécurité Infrastructure');

// ============================================================================
// Types
// ============================================================================

interface DockerAuditResult {
  issues: string[];
  score: number;
}

interface SecretDetection {
  type: string;
  line: number;
}

interface EnvValidation {
  valid: boolean;
  missing: string[];
  insecure: string[];
}

// ============================================================================
// Fonctions à implémenter
// ============================================================================

/**
 * Audite un Dockerfile (représenté par un tableau de lignes).
 * Vérifications :
 * - FROM avec :latest → "Évitez le tag :latest"
 * - Pas de directive USER → "Ajoutez une directive USER non-root"
 * - COPY ou ADD de .env → "Ne copiez pas les fichiers .env"
 * - RUN npm install sans --production → "Utilisez npm ci --production"
 * Score = 100 - (issues.length * 25), minimum 0.
 */
function auditDockerfile(lines: string[]): DockerAuditResult {
  // TODO: Implémenter l'audit Dockerfile
  return { issues: [], score: 100 };
}

/**
 * Détecte les secrets dans un texte (multi-lignes).
 * Patterns à détecter :
 * - Clés API : chaînes commençant par 'sk-', 'pk_', 'AKIA'
 * - Mots de passe : assignments comme password=xxx, passwd=xxx, SECRET_KEY=xxx
 * Retourne le type et le numéro de ligne (1-indexé).
 */
function detectSecrets(text: string): SecretDetection[] {
  // TODO: Implémenter la détection de secrets
  return [];
}

/**
 * Masque les données sensibles dans une entrée de log JSON.
 * Remplace les valeurs des champs spécifiés par '[REDACTED]'.
 * L'entrée est une chaîne JSON, retourne une chaîne JSON modifiée.
 */
function redactSensitiveData(logEntry: string, fields: string[]): string {
  // TODO: Implémenter le masquage
  return logEntry;
}

/**
 * Valide une configuration d'environnement.
 * - Vérifie que toutes les clés requises sont présentes.
 * - Flag comme insécure si une valeur contient 'password', '1234' ou 'admin'.
 */
function validateEnvironmentConfig(
  config: Record<string, string>,
  required: string[]
): EnvValidation {
  // TODO: Implémenter la validation
  return { valid: true, missing: [], insecure: [] };
}

// ============================================================================
// Tests
// ============================================================================

await test('auditDockerfile — détecte le tag :latest', async () => {
  const result = auditDockerfile([
    'FROM node:latest',
    'WORKDIR /app',
    'COPY . .',
    'RUN npm install',
  ]);
  assert(result.issues.some(i => i.includes(':latest')));
});

await test('auditDockerfile — détecte l\'absence de USER', async () => {
  const result = auditDockerfile([
    'FROM node:18',
    'WORKDIR /app',
    'COPY . .',
    'RUN npm install',
  ]);
  assert(result.issues.some(i => i.includes('USER')));
});

await test('auditDockerfile — score parfait', async () => {
  const result = auditDockerfile([
    'FROM node:18-alpine',
    'WORKDIR /app',
    'COPY package*.json ./',
    'RUN npm ci --production',
    'COPY . .',
    'USER node',
    'CMD ["node", "server.js"]',
  ]);
  assertEqual(result.issues.length, 0);
  assertEqual(result.score, 100);
});

await test('auditDockerfile — calcul du score', async () => {
  const result = auditDockerfile([
    'FROM node:latest',
    'COPY .env .',
    'RUN npm install',
  ]);
  assert(result.score <= 25);
  assert(result.issues.length >= 3);
});

await test('detectSecrets — détecte les clés API et mots de passe', async () => {
  const text = `const config = {
  apiKey: "sk-abc123def456",
  password=mysecretpassword
  region: "eu-west-1"
  accessKey: "AKIAIOSFODNN7EXAMPLE"
}`;
  const result = detectSecrets(text);
  assert(result.length >= 3);
  assert(result.some(r => r.type === 'api_key'));
  assert(result.some(r => r.type === 'password'));
});

await test('redactSensitiveData — masque les champs spécifiés', async () => {
  const log = '{"user":"alice","password":"secret123","action":"login"}';
  const result = JSON.parse(redactSensitiveData(log, ['password']));
  assertEqual(result.password, '[REDACTED]');
  assertEqual(result.user, 'alice');
});

await test('validateEnvironmentConfig — détecte les clés manquantes', async () => {
  const result = validateEnvironmentConfig(
    { DATABASE_URL: 'postgres://localhost', NODE_ENV: 'production' },
    ['DATABASE_URL', 'NODE_ENV', 'SECRET_KEY']
  );
  assert(!result.valid);
  assert(result.missing.includes('SECRET_KEY'));
});

await test('validateEnvironmentConfig — détecte les valeurs insécurisées', async () => {
  const result = validateEnvironmentConfig(
    { DATABASE_URL: 'postgres://localhost', SECRET_KEY: 'password', ADMIN_TOKEN: 'admin1234' },
    ['DATABASE_URL', 'SECRET_KEY', 'ADMIN_TOKEN']
  );
  assert(result.insecure.includes('SECRET_KEY'));
  assert(result.insecure.includes('ADMIN_TOKEN'));
});

summary();
