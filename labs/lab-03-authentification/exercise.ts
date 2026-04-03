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
// Fonctions à implémenter
// ============================================================================

/**
 * Simule le hachage d'un mot de passe avec un sel.
 * Algorithme (simulation uniquement, PAS pour la production) :
 * Inverse la chaîne (password + salt), puis convertit chaque caractère en hexadécimal.
 * Return: Array.from(combined).reverse().map(c => c.charCodeAt(0).toString(16)).join('')
 */
function simulateHash(password: string, salt: string): string {
  // TODO: Simuler le hachage
  return '';
}

/**
 * Vérifie un mot de passe en le hachant et comparant avec le hash stocké.
 */
function verifyPassword(password: string, salt: string, storedHash: string): boolean {
  // TODO: Vérifier le mot de passe
  return false;
}

/**
 * Génère un sel déterministe de la longueur spécifiée.
 * Répète la chaîne "abcdef0123456789" et prend les N premiers caractères.
 */
function generateSalt(length: number): string {
  // TODO: Générer le sel
  return '';
}

/**
 * Parse un token JWT (format: header.payload.signature).
 * Décode le header et le payload en base64.
 * Retourne { header, payload, signature }.
 */
function parseJWT(token: string): JWTParts {
  // TODO: Parser le JWT
  return { header: {}, payload: {}, signature: '' };
}

/**
 * Vérifie si un token est expiré.
 * Compare le champ `exp` (en secondes) avec l'heure actuelle.
 * Le paramètre `now` permet de contrôler l'heure pour les tests.
 */
function isTokenExpired(payload: { exp: number }, now?: number): boolean {
  // TODO: Vérifier l'expiration
  return false;
}

/**
 * Évalue la robustesse d'un mot de passe.
 * Score 0-5 : +1 pour longueur >= 8, +1 majuscule, +1 minuscule, +1 chiffre, +1 caractère spécial.
 * feedback : tableau des critères manquants.
 */
function checkPasswordStrength(password: string): PasswordStrength {
  // TODO: Évaluer la robustesse
  return { score: 0, feedback: [] };
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
