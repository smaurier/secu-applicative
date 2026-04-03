import { createTestRunner } from '../test-utils.js';
const { test, assert, assertEqual, assertDeepEqual, summary } = createTestRunner('Lab 03 — Authentification');

// ============================================================================
// Types
// ============================================================================

interface PasswordStrength {
  score: number;
  feedback: string[];
}

interface JWTParts {
  header: any;
  payload: any;
  signature: string;
}

// ============================================================================
// Implémentations
// ============================================================================

function simulateHash(password: string, salt: string): string {
  const combined = password + salt;
  return Array.from(combined)
    .reverse()
    .map((c) => c.charCodeAt(0).toString(16))
    .join('');
}

function verifyPassword(password: string, salt: string, storedHash: string): boolean {
  return simulateHash(password, salt) === storedHash;
}

function generateSalt(length: number): string {
  const chars = 'abcdef0123456789';
  let salt = '';
  for (let i = 0; i < length; i++) {
    salt += chars[i % chars.length];
  }
  return salt;
}

function parseJWT(token: string): JWTParts {
  const [headerB64, payloadB64, signature] = token.split('.');
  const header = JSON.parse(Buffer.from(headerB64, 'base64').toString('utf-8'));
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf-8'));
  return { header, payload, signature };
}

function isTokenExpired(payload: { exp: number }, now?: number): boolean {
  const currentTime = now ?? Math.floor(Date.now() / 1000);
  return payload.exp < currentTime;
}

function checkPasswordStrength(password: string): PasswordStrength {
  const feedback: string[] = [];
  let score = 0;

  if (password.length >= 8) {
    score++;
  } else {
    feedback.push('Le mot de passe doit contenir au moins 8 caractères');
  }

  if (/[A-Z]/.test(password)) {
    score++;
  } else {
    feedback.push('Ajoutez au moins une lettre majuscule');
  }

  if (/[a-z]/.test(password)) {
    score++;
  } else {
    feedback.push('Ajoutez au moins une lettre minuscule');
  }

  if (/[0-9]/.test(password)) {
    score++;
  } else {
    feedback.push('Ajoutez au moins un chiffre');
  }

  if (/[^A-Za-z0-9]/.test(password)) {
    score++;
  } else {
    feedback.push('Ajoutez au moins un caractère spécial');
  }

  return { score, feedback };
}

// ============================================================================
// Tests
// ============================================================================

await test('simulateHash — produit un hash déterministe', async () => {
  const hash1 = simulateHash('password', 'salt123');
  const hash2 = simulateHash('password', 'salt123');
  assertEqual(hash1, hash2);
  assert(hash1.length > 0, 'Le hash ne doit pas être vide');
});

await test('verifyPassword — vérifie correctement le mot de passe', async () => {
  const salt = 'mysalt';
  const hash = simulateHash('secret', salt);
  assert(verifyPassword('secret', salt, hash), 'Devrait valider le bon mot de passe');
  assert(!verifyPassword('wrong', salt, hash), 'Devrait rejeter un mauvais mot de passe');
});

await test('generateSalt — génère un sel de la bonne longueur', async () => {
  assertEqual(generateSalt(8), 'abcdef01');
  assertEqual(generateSalt(16), 'abcdef0123456789');
  assertEqual(generateSalt(20).length, 20);
});

await test('parseJWT — décode un token JWT valide', async () => {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
  const payload = Buffer.from(JSON.stringify({ sub: '1234', name: 'Alice', exp: 9999999999 })).toString('base64');
  const token = `${header}.${payload}.signature123`;

  const parsed = parseJWT(token);
  assertEqual(parsed.header.alg, 'HS256');
  assertEqual(parsed.payload.name, 'Alice');
  assertEqual(parsed.signature, 'signature123');
});

await test('isTokenExpired — détecte un token expiré', async () => {
  assert(isTokenExpired({ exp: 1000 }, 2000), 'Token dans le passé devrait être expiré');
  assert(!isTokenExpired({ exp: 3000 }, 2000), 'Token dans le futur ne devrait pas être expiré');
});

await test('checkPasswordStrength — mot de passe faible', async () => {
  const result = checkPasswordStrength('abc');
  assert(result.score < 3, 'Score devrait être faible');
  assert(result.feedback.length > 0, 'Devrait avoir des suggestions');
});

await test('checkPasswordStrength — mot de passe fort', async () => {
  const result = checkPasswordStrength('C0mpl3x!Pass');
  assertEqual(result.score, 5);
  assertEqual(result.feedback.length, 0);
});

await test('checkPasswordStrength — feedback correct pour critères manquants', async () => {
  const result = checkPasswordStrength('abcdefgh');
  assert(result.score >= 2, 'Score devrait inclure longueur et minuscules');
  assert(result.feedback.some(f => f.toLowerCase().includes('majuscule')), 'Devrait demander une majuscule');
  assert(result.feedback.some(f => f.toLowerCase().includes('chiffre')), 'Devrait demander un chiffre');
});

summary();
