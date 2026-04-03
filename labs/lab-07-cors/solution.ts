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
// Implémentations
// ============================================================================

function isSimpleRequest(method: string, headers: string[]): boolean {
  const simpleMethods = ['GET', 'HEAD', 'POST'];
  const simpleHeaders = ['accept', 'accept-language', 'content-language', 'content-type'];
  if (!simpleMethods.includes(method.toUpperCase())) return false;
  return headers.every(h => simpleHeaders.includes(h.toLowerCase()));
}

function validateCORSConfig(config: CORSConfig): CORSValidation {
  const errors: string[] = [];
  const validMethods = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'];

  if (config.credentials && config.origin === '*') {
    errors.push("L'origine '*' n'est pas autorisée avec credentials");
  }

  for (const method of config.methods) {
    if (!validMethods.includes(method.toUpperCase())) {
      errors.push(`Méthode invalide : ${method}`);
    }
  }

  return { valid: errors.length === 0, errors };
}

function simulatePreflight(request: PreflightRequest, config: PreflightConfig): PreflightResponse {
  const originAllowed = config.allowedOrigins.includes(request.origin);
  const methodAllowed = config.allowedMethods.includes(request.method);

  if (!originAllowed || !methodAllowed) {
    return { status: 403, headers: {} };
  }

  return {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': request.origin,
      'Access-Control-Allow-Methods': config.allowedMethods.join(', '),
      'Access-Control-Allow-Headers': config.allowedHeaders.join(', '),
      'Access-Control-Max-Age': String(config.maxAge),
    },
  };
}

function matchOrigin(requestOrigin: string, allowedOrigins: string[]): string | null {
  for (const allowed of allowedOrigins) {
    if (allowed === requestOrigin) return allowed;
    if (allowed.includes('*')) {
      const escaped = allowed.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace('*', '[^.]+');
      const regex = new RegExp(`^${escaped}$`);
      if (regex.test(requestOrigin)) return allowed;
    }
  }
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
