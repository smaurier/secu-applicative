import { createTestRunner } from '../test-utils.js';
const { test, assert, assertEqual, assertDeepEqual, summary } = createTestRunner('Lab 08 — Sécurité des APIs');

// ============================================================================
// Types
// ============================================================================

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
}

interface ValidationSchema {
  type: string;
  required?: boolean;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
}

interface ValidationResult {
  valid: boolean;
  errors: string[];
}

interface GraphQLDepthResult {
  safe: boolean;
  depth: number;
}

// ============================================================================
// Fonctions à implémenter
// ============================================================================

/**
 * Crée un rate limiter à fenêtre glissante.
 * maxRequests : nombre maximum de requêtes dans la fenêtre.
 * windowMs : durée de la fenêtre en millisecondes.
 * check(clientId, now?) : vérifie si le client peut faire une requête.
 * Les timestamps hors de la fenêtre sont nettoyés à chaque appel.
 */
function createRateLimiter(maxRequests: number, windowMs: number): {
  check: (clientId: string, now?: number) => RateLimitResult;
} {
  // TODO: Implémenter le rate limiter
  return {
    check: (_clientId: string, _now?: number) => ({ allowed: false, remaining: 0, resetAt: 0 })
  };
}

/**
 * Valide une entrée selon un schéma.
 * Vérifications :
 * - required : la valeur ne doit pas être undefined/null/''
 * - type : 'string' | 'number' → typeof doit correspondre
 * - minLength / maxLength : pour les strings
 * - pattern : regex à satisfaire pour les strings
 */
function validateAPIInput(input: any, schema: ValidationSchema): ValidationResult {
  // TODO: Implémenter la validation
  return { valid: true, errors: [] };
}

/**
 * Filtre les champs d'un objet pour ne garder que ceux autorisés.
 * Supporte la notation pointée pour les champs imbriqués (ex: 'user.name').
 */
function filterResponse(data: Record<string, any>, allowedFields: string[]): Record<string, any> {
  // TODO: Implémenter le filtrage
  return {};
}

/**
 * Détecte les attaques par profondeur dans une requête GraphQL simplifiée.
 * Compte la profondeur maximale d'imbrication des accolades { }.
 * safe = depth <= maxDepth
 */
function detectGraphQLDepthAttack(query: string, maxDepth: number): GraphQLDepthResult {
  // TODO: Implémenter la détection de profondeur
  return { safe: true, depth: 0 };
}

/**
 * Génère une clé d'idempotence à partir de method + path + body.
 * Utilise un hachage simple : let hash = 0; for (const c of str) hash = ((hash << 5) - hash + c.charCodeAt(0)) | 0;
 * Retourne le hash en hexadécimal avec (hash >>> 0).toString(16).
 */
function generateIdempotencyKey(method: string, path: string, body: string): string {
  // TODO: Implémenter la génération de clé
  return '';
}

// ============================================================================
// Tests
// ============================================================================

await test('createRateLimiter — autorise les requêtes dans la limite', async () => {
  const limiter = createRateLimiter(3, 1000);
  const r1 = limiter.check('client1', 0);
  const r2 = limiter.check('client1', 100);
  const r3 = limiter.check('client1', 200);
  assert(r1.allowed);
  assert(r2.allowed);
  assert(r3.allowed);
  assertEqual(r3.remaining, 0);
});

await test('createRateLimiter — bloque après la limite', async () => {
  const limiter = createRateLimiter(2, 1000);
  limiter.check('client1', 0);
  limiter.check('client1', 100);
  const r3 = limiter.check('client1', 200);
  assert(!r3.allowed);
  assertEqual(r3.remaining, 0);
});

await test('createRateLimiter — réinitialise après la fenêtre', async () => {
  const limiter = createRateLimiter(2, 1000);
  limiter.check('client1', 0);
  limiter.check('client1', 100);
  const r3 = limiter.check('client1', 1500);
  assert(r3.allowed);
});

await test('validateAPIInput — valide une entrée correcte', async () => {
  const result = validateAPIInput('hello', { type: 'string', required: true, minLength: 3, maxLength: 10 });
  assert(result.valid);
  assertEqual(result.errors.length, 0);
});

await test('validateAPIInput — détecte les erreurs', async () => {
  const result = validateAPIInput('', { type: 'string', required: true, minLength: 3 });
  assert(!result.valid);
  assert(result.errors.length > 0);
});

await test('filterResponse — filtre les champs autorisés', async () => {
  const data = { id: 1, name: 'Alice', password: 'secret', user: { name: 'Alice', email: 'a@b.com', role: 'admin' } };
  const result = filterResponse(data, ['id', 'name', 'user.name']);
  assertEqual(result.id, 1);
  assertEqual(result.name, 'Alice');
  assertEqual(result.user.name, 'Alice');
  assertEqual(result.password, undefined);
  assertEqual(result.user.email, undefined);
});

await test('detectGraphQLDepthAttack — détecte une profondeur excessive', async () => {
  const query = '{ user { posts { comments { author { name } } } } }';
  const result = detectGraphQLDepthAttack(query, 3);
  assert(!result.safe);
  assertEqual(result.depth, 5);
});

await test('generateIdempotencyKey — génère des clés cohérentes', async () => {
  const key1 = generateIdempotencyKey('POST', '/api/orders', '{"item":"book"}');
  const key2 = generateIdempotencyKey('POST', '/api/orders', '{"item":"book"}');
  const key3 = generateIdempotencyKey('POST', '/api/orders', '{"item":"pen"}');
  assertEqual(key1, key2);
  assert(key1 !== key3);
});

summary();
