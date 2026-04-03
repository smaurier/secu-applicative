import { createTestRunner } from '../test-utils.js';
const { test, assert, assertEqual, assertDeepEqual, summary } = createTestRunner('Lab 02 — Injection');

// ============================================================================
// Types
// ============================================================================

interface ValidationResult {
  valid: boolean;
  errors: string[];
}

interface ValidationRules {
  maxLength?: number;
  pattern?: RegExp;
  allowedChars?: string;
}

interface ParameterizedQuery {
  query: string;
  values: string[];
}

// ============================================================================
// Implémentations
// ============================================================================

function sanitizeHTML(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function escapeSQL(input: string): string {
  return input
    .replace(/'/g, "''")
    .replace(/;/g, '')
    .replace(/--/g, '');
}

function buildParameterizedQuery(template: string, params: Record<string, string>): ParameterizedQuery {
  const values: string[] = [];
  let index = 1;
  const query = template.replace(/:([a-zA-Z_]+)/g, (_match, key) => {
    values.push(params[key]);
    return `$${index++}`;
  });
  return { query, values };
}

function detectXSSPayload(input: string): boolean {
  const lower = input.toLowerCase();
  const patterns = [
    '<script',
    'javascript:',
    'onerror=',
    'onload=',
    '<img',
    'eval(',
  ];
  return patterns.some((p) => lower.includes(p));
}

function sanitizeFilePath(input: string): string {
  let path = input;
  path = path.replace(/\0/g, '');
  path = path.replace(/\\/g, '/');
  // Remove ../ sequences repeatedly until none remain
  while (path.includes('../')) {
    path = path.replace(/\.\.\//g, '');
  }
  // Remove leading slashes
  path = path.replace(/^\/+/, '');
  return path;
}

function validateInput(input: string, rules: ValidationRules): ValidationResult {
  const errors: string[] = [];

  if (rules.maxLength !== undefined && input.length > rules.maxLength) {
    errors.push(`La longueur dépasse le maximum de ${rules.maxLength} caractères`);
  }

  if (rules.pattern && !rules.pattern.test(input)) {
    errors.push('L\'entrée ne correspond pas au pattern requis');
  }

  if (rules.allowedChars) {
    const disallowed = [...input].filter((c) => !rules.allowedChars!.includes(c));
    if (disallowed.length > 0) {
      errors.push(`Caractères non autorisés : ${[...new Set(disallowed)].join(', ')}`);
    }
  }

  return { valid: errors.length === 0, errors };
}

// ============================================================================
// Tests
// ============================================================================

await test('sanitizeHTML — échappe les caractères dangereux', async () => {
  assertEqual(sanitizeHTML('<script>alert("XSS")</script>'), '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');
  assertEqual(sanitizeHTML("it's a <b>test</b> & more"), "it&#x27;s a &lt;b&gt;test&lt;/b&gt; &amp; more");
});

await test('escapeSQL — échappe les apostrophes et supprime les dangers', async () => {
  assertEqual(escapeSQL("O'Reilly"), "O''Reilly");
  assertEqual(escapeSQL("admin'; DROP TABLE users--"), "admin'' DROP TABLE users");
});

await test('buildParameterizedQuery — construit la requête correctement', async () => {
  const result = buildParameterizedQuery(
    'SELECT * FROM users WHERE name = :name AND role = :role',
    { name: 'Alice', role: 'admin' }
  );
  assertEqual(result.query, 'SELECT * FROM users WHERE name = $1 AND role = $2');
  assertDeepEqual(result.values, ['Alice', 'admin']);
});

await test('detectXSSPayload — détecte les payloads malveillants', async () => {
  assert(detectXSSPayload('<script>alert(1)</script>'), 'Devrait détecter <script>');
  assert(detectXSSPayload('<img src=x onerror=alert(1)>'), 'Devrait détecter onerror');
  assert(detectXSSPayload('javascript:alert(1)'), 'Devrait détecter javascript:');
  assert(detectXSSPayload('eval(document.cookie)'), 'Devrait détecter eval(');
});

await test('detectXSSPayload — accepte les entrées sûres', async () => {
  assert(!detectXSSPayload('Bonjour le monde'), 'Texte simple');
  assert(!detectXSSPayload('user@example.com'), 'Email valide');
});

await test('sanitizeFilePath — supprime les traversées de répertoire', async () => {
  assertEqual(sanitizeFilePath('../../etc/passwd'), 'etc/passwd');
  assertEqual(sanitizeFilePath('uploads\\..\\..\\secret.txt'), 'uploads/secret.txt');
  assertEqual(sanitizeFilePath('/root/file.txt'), 'root/file.txt');
});

await test('validateInput — vérifie la longueur maximale', async () => {
  const result = validateInput('hello world', { maxLength: 5 });
  assertEqual(result.valid, false);
  assert(result.errors.length > 0, 'Devrait avoir des erreurs');
});

await test('validateInput — vérifie le pattern et les caractères autorisés', async () => {
  const result = validateInput('abc123!', { pattern: /^[a-z0-9]+$/, allowedChars: 'abcdefghijklmnopqrstuvwxyz0123456789' });
  assertEqual(result.valid, false);
  assert(result.errors.length > 0, 'Devrait avoir des erreurs pour le ! non autorisé');
});

summary();
