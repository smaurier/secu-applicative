import { createTestRunner } from '../test-utils.js';
const { test, assert, assertEqual, assertDeepEqual, summary } = createTestRunner('Lab 07 — CORS : Configuration et Validation');

// ============================================================================
// Types
// ============================================================================

interface CORSConfig {
  origin: string | string[];
  methods: string[];
  credentials: boolean;
}

interface CORSValidation {
  valid: boolean;
  errors: string[];
}

interface PreflightRequest {
  origin: string;
  method: string;
  headers: string[];
}

interface PreflightConfig {
  allowedOrigins: string[];
  allowedMethods: string[];
  allowedHeaders: string[];
  maxAge: number;
}

interface PreflightResponse {
  status: number;
  headers: Record<string, string>;
}

// ============================================================================
// Fonctions à implémenter
// ============================================================================

/**
 * Vérifie si une requête est une requête "simple" (pas de préflight).
 * Méthode doit être GET, HEAD ou POST.
 * Les en-têtes doivent être uniquement parmi : Accept, Accept-Language, Content-Language, Content-Type.
 */
function isSimpleRequest(method: string, headers: string[]): boolean {
  // TODO: Implémenter la vérification de requête simple
  return false;
}

/**
 * Valide une configuration CORS.
 * Erreurs possibles :
 * - credentials=true avec origin='*' → "L'origine '*' n'est pas autorisée avec credentials"
 * - méthodes invalides (hors GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS) → "Méthode invalide : XXX"
 */
function validateCORSConfig(config: CORSConfig): CORSValidation {
  // TODO: Implémenter la validation de configuration CORS
  return { valid: true, errors: [] };
}

/**
 * Simule une requête préflight OPTIONS.
 * Si l'origine est autorisée et la méthode est autorisée → status 204 avec en-têtes CORS.
 * Sinon → status 403, en-têtes vides.
 * En-têtes retournés (si autorisé) :
 *   Access-Control-Allow-Origin, Access-Control-Allow-Methods,
 *   Access-Control-Allow-Headers, Access-Control-Max-Age
 */
function simulatePreflight(request: PreflightRequest, config: PreflightConfig): PreflightResponse {
  // TODO: Implémenter la simulation de préflight
  return { status: 403, headers: {} };
}

/**
 * Vérifie si une origine correspond aux origines autorisées.
 * Supporte les patterns wildcard : 'https://*.example.com' matche 'https://api.example.com'.
 * Retourne l'origine correspondante ou null.
 */
function matchOrigin(requestOrigin: string, allowedOrigins: string[]): string | null {
  // TODO: Implémenter le matching d'origines
  return null;
}

// ============================================================================
// Tests
// ============================================================================

await test('isSimpleRequest — requête GET simple', async () => {
  assert(isSimpleRequest('GET', ['Accept', 'Accept-Language']));
  assert(isSimpleRequest('POST', ['Content-Type']));
  assert(isSimpleRequest('HEAD', []));
});

await test('isSimpleRequest — requête non simple', async () => {
  assert(!isSimpleRequest('PUT', ['Content-Type']));
  assert(!isSimpleRequest('GET', ['Authorization']));
  assert(!isSimpleRequest('DELETE', []));
});

await test('validateCORSConfig — configuration valide', async () => {
  const result = validateCORSConfig({
    origin: 'https://example.com',
    methods: ['GET', 'POST'],
    credentials: true
  });
  assert(result.valid);
  assertEqual(result.errors.length, 0);
});

await test('validateCORSConfig — erreurs détectées', async () => {
  const result = validateCORSConfig({
    origin: '*',
    methods: ['GET', 'INVALID'],
    credentials: true
  });
  assert(!result.valid);
  assertEqual(result.errors.length, 2);
});

await test('simulatePreflight — requête autorisée', async () => {
  const result = simulatePreflight(
    { origin: 'https://app.example.com', method: 'POST', headers: ['Content-Type'] },
    { allowedOrigins: ['https://app.example.com'], allowedMethods: ['GET', 'POST'], allowedHeaders: ['Content-Type'], maxAge: 86400 }
  );
  assertEqual(result.status, 204);
  assertEqual(result.headers['Access-Control-Allow-Origin'], 'https://app.example.com');
});

await test('simulatePreflight — requête refusée', async () => {
  const result = simulatePreflight(
    { origin: 'https://evil.com', method: 'DELETE', headers: [] },
    { allowedOrigins: ['https://app.example.com'], allowedMethods: ['GET', 'POST'], allowedHeaders: [], maxAge: 86400 }
  );
  assertEqual(result.status, 403);
});

await test('matchOrigin — correspondance exacte', async () => {
  assertEqual(matchOrigin('https://app.example.com', ['https://app.example.com', 'https://other.com']), 'https://app.example.com');
  assertEqual(matchOrigin('https://unknown.com', ['https://app.example.com']), null);
});

await test('matchOrigin — pattern wildcard', async () => {
  assertEqual(matchOrigin('https://api.example.com', ['https://*.example.com']), 'https://*.example.com');
  assertEqual(matchOrigin('https://api.other.com', ['https://*.example.com']), null);
});

summary();
