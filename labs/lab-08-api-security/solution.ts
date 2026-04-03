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
// Implémentations
// ============================================================================

function createRateLimiter(maxRequests: number, windowMs: number): {
  check: (clientId: string, now?: number) => RateLimitResult;
} {
  const requests = new Map<string, number[]>();

  return {
    check(clientId: string, now: number = Date.now()): RateLimitResult {
      const windowStart = now - windowMs;
      const timestamps = (requests.get(clientId) ?? []).filter(t => t > windowStart);

      if (timestamps.length >= maxRequests) {
        requests.set(clientId, timestamps);
        return {
          allowed: false,
          remaining: 0,
          resetAt: timestamps[0] + windowMs,
        };
      }

      timestamps.push(now);
      requests.set(clientId, timestamps);

      return {
        allowed: true,
        remaining: maxRequests - timestamps.length,
        resetAt: timestamps[0] + windowMs,
      };
    },
  };
}

function validateAPIInput(input: any, schema: ValidationSchema): ValidationResult {
  const errors: string[] = [];

  if (schema.required && (input === undefined || input === null || input === '')) {
    errors.push('Le champ est requis');
  }

  if (input !== undefined && input !== null && input !== '') {
    if (typeof input !== schema.type) {
      errors.push(`Type attendu : ${schema.type}, reçu : ${typeof input}`);
    }

    if (schema.type === 'string' && typeof input === 'string') {
      if (schema.minLength !== undefined && input.length < schema.minLength) {
        errors.push(`Longueur minimale : ${schema.minLength}`);
      }
      if (schema.maxLength !== undefined && input.length > schema.maxLength) {
        errors.push(`Longueur maximale : ${schema.maxLength}`);
      }
      if (schema.pattern && !new RegExp(schema.pattern).test(input)) {
        errors.push(`Ne correspond pas au pattern : ${schema.pattern}`);
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

function filterResponse(data: Record<string, any>, allowedFields: string[]): Record<string, any> {
  const result: Record<string, any> = {};

  for (const field of allowedFields) {
    const parts = field.split('.');
    if (parts.length === 1) {
      if (data[field] !== undefined) {
        result[field] = data[field];
      }
    } else {
      const [parent, ...rest] = parts;
      const child = rest.join('.');
      if (data[parent] !== undefined && typeof data[parent] === 'object') {
        if (!result[parent]) result[parent] = {};
        const value = rest.reduce((obj, key) => obj?.[key], data[parent]);
        if (value !== undefined) {
          let current = result[parent];
          for (let i = 0; i < rest.length - 1; i++) {
            if (!current[rest[i]]) current[rest[i]] = {};
            current = current[rest[i]];
          }
          current[rest[rest.length - 1]] = value;
        }
      }
    }
  }

  return result;
}

function detectGraphQLDepthAttack(query: string, maxDepth: number): GraphQLDepthResult {
  let depth = 0;
  let maxFound = 0;

  for (const char of query) {
    if (char === '{') {
      depth++;
      if (depth > maxFound) maxFound = depth;
    } else if (char === '}') {
      depth--;
    }
  }

  return { safe: maxFound <= maxDepth, depth: maxFound };
}

function generateIdempotencyKey(method: string, path: string, body: string): string {
  const str = `${method}:${path}:${body}`;
  let hash = 0;
  for (const c of str) {
    hash = ((hash << 5) - hash + c.charCodeAt(0)) | 0;
  }
  return (hash >>> 0).toString(16);
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
