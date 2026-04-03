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
// Implémentations
// ============================================================================

function auditDockerfile(lines: string[]): DockerAuditResult {
  const issues: string[] = [];

  const hasUser = lines.some(l => /^USER\s+/i.test(l.trim()));
  if (!hasUser) {
    issues.push('Ajoutez une directive USER non-root');
  }

  for (const line of lines) {
    const trimmed = line.trim();

    if (/^FROM\s+\S+:latest/i.test(trimmed)) {
      issues.push('Évitez le tag :latest');
    }

    if (/^(COPY|ADD)\s+.*\.env/i.test(trimmed)) {
      issues.push('Ne copiez pas les fichiers .env');
    }

    if (/^RUN\s+npm\s+install/i.test(trimmed) && !trimmed.includes('--production')) {
      issues.push('Utilisez npm ci --production');
    }
  }

  const score = Math.max(0, 100 - issues.length * 25);
  return { issues, score };
}

function detectSecrets(text: string): SecretDetection[] {
  const results: SecretDetection[] = [];
  const lines = text.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    if (/sk-[a-zA-Z0-9]+/.test(line) || /pk_[a-zA-Z0-9]+/.test(line)) {
      results.push({ type: 'api_key', line: lineNum });
    }

    if (/AKIA[A-Z0-9]{12,}/.test(line)) {
      results.push({ type: 'aws_access_key', line: lineNum });
    }

    if (/(?:password|passwd|SECRET_KEY)\s*=\s*\S+/i.test(line)) {
      results.push({ type: 'password', line: lineNum });
    }
  }

  return results;
}

function redactSensitiveData(logEntry: string, fields: string[]): string {
  const parsed = JSON.parse(logEntry);

  for (const field of fields) {
    if (field in parsed) {
      parsed[field] = '[REDACTED]';
    }
  }

  return JSON.stringify(parsed);
}

function validateEnvironmentConfig(
  config: Record<string, string>,
  required: string[]
): EnvValidation {
  const missing: string[] = [];
  const insecure: string[] = [];

  for (const key of required) {
    if (!(key in config)) {
      missing.push(key);
    }
  }

  for (const [key, value] of Object.entries(config)) {
    const lower = value.toLowerCase();
    if (lower.includes('password') || lower.includes('1234') || lower.includes('admin')) {
      insecure.push(key);
    }
  }

  const valid = missing.length === 0 && insecure.length === 0;
  return { valid, missing, insecure };
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
