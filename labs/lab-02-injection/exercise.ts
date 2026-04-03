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
// Fonctions à implémenter
// ============================================================================

/**
 * Sanitise le HTML en remplaçant les caractères dangereux par des entités.
 * & → &amp;  < → &lt;  > → &gt;  " → &quot;  ' → &#x27;
 */
function sanitizeHTML(input: string): string {
  // TODO: Remplacer les caractères dangereux
  return input;
}

/**
 * Échappe les entrées pour prévenir l'injection SQL.
 * - Double les apostrophes (')
 * - Supprime les points-virgules (;)
 * - Supprime les commentaires SQL (--)
 */
function escapeSQL(input: string): string {
  // TODO: Échapper les caractères dangereux pour SQL
  return input;
}

/**
 * Construit une requête paramétrée à partir d'un template et de paramètres.
 * Template : "SELECT * FROM users WHERE name = :name AND role = :role"
 * Params : { name: "Alice", role: "admin" }
 * Résultat : { query: "SELECT * FROM users WHERE name = $1 AND role = $2", values: ["Alice", "admin"] }
 */
function buildParameterizedQuery(template: string, params: Record<string, string>): ParameterizedQuery {
  // TODO: Construire la requête paramétrée
  return { query: '', values: [] };
}

/**
 * Détecte la présence de payloads XSS dans une chaîne.
 * Vérifie : <script>, javascript:, onerror=, onload=, <img src=x onerror, eval(
 */
function detectXSSPayload(input: string): boolean {
  // TODO: Détecter les payloads XSS
  return false;
}

/**
 * Assainit un chemin de fichier.
 * - Supprime les séquences ../ et ..\
 * - Supprime les octets nuls (\0)
 * - Normalise vers des slashs (/)
 * - Ne doit pas commencer par /
 */
function sanitizeFilePath(input: string): string {
  // TODO: Assainir le chemin de fichier
  return input;
}

/**
 * Valide une entrée selon des règles configurables.
 * - maxLength : longueur maximale
 * - pattern : expression régulière à respecter
 * - allowedChars : chaîne contenant les caractères autorisés
 * Retourne { valid: boolean, errors: string[] }
 */
function validateInput(input: string, rules: ValidationRules): ValidationResult {
  // TODO: Valider l'entrée selon les règles
  return { valid: true, errors: [] };
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
