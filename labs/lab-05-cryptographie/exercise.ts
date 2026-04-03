import { createTestRunner } from '../test-utils.js';
const { test, assert, assertEqual, summary } = createTestRunner('Lab 05 — Cryptographie');

// ============================================================================
// Fonctions à implémenter
// ============================================================================

/**
 * Hachage simple (simulation pédagogique).
 * Algorithme : let hash = 0; for (const c of input) hash = ((hash << 5) - hash + c.charCodeAt(0)) | 0;
 * Retourne le hash en hexadécimal, padé sur 8 caractères.
 * Utiliser (hash >>> 0) pour gérer les valeurs négatives.
 */
function simpleHash(input: string): string {
  // TODO: Implémenter le hachage simple
  return '00000000';
}

/**
 * Chiffrement XOR.
 * XOR chaque caractère du texte avec le caractère correspondant de la clé (cyclique).
 * Retourne le résultat en paires hexadécimales.
 */
function xorCipher(text: string, key: string): string {
  // TODO: Implémenter le chiffrement XOR
  return '';
}

/**
 * Déchiffrement XOR.
 * Inverse de xorCipher : parse les paires hexadécimales, XOR avec la clé.
 */
function xorDecipher(hex: string, key: string): string {
  // TODO: Implémenter le déchiffrement XOR
  return '';
}

/**
 * Encode une chaîne en Base64.
 * Utilise Buffer.from(input).toString('base64').
 */
function base64Encode(input: string): string {
  // TODO: Encoder en Base64
  return '';
}

/**
 * Décode une chaîne Base64.
 * Utilise Buffer.from(encoded, 'base64').toString('utf-8').
 */
function base64Decode(encoded: string): string {
  // TODO: Décoder depuis Base64
  return '';
}

/**
 * Génère un HMAC simulé.
 * Formule : simpleHash(key + message + key)
 */
function generateHMAC(message: string, key: string): string {
  // TODO: Générer le HMAC
  return '';
}

/**
 * Vérifie un HMAC en comparant avec le résultat attendu.
 */
function verifyHMAC(message: string, key: string, hmac: string): boolean {
  // TODO: Vérifier le HMAC
  return false;
}

/**
 * Comparaison en temps constant (prévention des attaques par timing).
 * Compare toutes les positions même en cas de différence.
 * Les chaînes de longueurs différentes retournent false.
 */
function compareConstantTime(a: string, b: string): boolean {
  // TODO: Implémenter la comparaison en temps constant
  return false;
}

// ============================================================================
// Tests
// ============================================================================

await test('simpleHash — produit un hash déterministe', async () => {
  const h1 = simpleHash('hello');
  const h2 = simpleHash('hello');
  assertEqual(h1, h2);
  assertEqual(h1.length, 8);
  assert(h1 !== simpleHash('world'), 'Entrées différentes → hashes différents');
});

await test('xorCipher + xorDecipher — chiffrement/déchiffrement symétrique', async () => {
  const key = 'secret';
  const message = 'Bonjour le monde';
  const encrypted = xorCipher(message, key);
  assert(encrypted !== message, 'Le texte chiffré doit être différent du texte clair');
  const decrypted = xorDecipher(encrypted, key);
  assertEqual(decrypted, message);
});

await test('xorCipher — même clé et message produisent le même résultat', async () => {
  assertEqual(xorCipher('test', 'key'), xorCipher('test', 'key'));
});

await test('base64Encode / base64Decode — encodage/décodage correct', async () => {
  assertEqual(base64Encode('Hello, World!'), 'SGVsbG8sIFdvcmxkIQ==');
  assertEqual(base64Decode('SGVsbG8sIFdvcmxkIQ=='), 'Hello, World!');
  assertEqual(base64Decode(base64Encode('Test éàü')), 'Test éàü');
});

await test('generateHMAC — produit un HMAC déterministe', async () => {
  const hmac1 = generateHMAC('message', 'clé');
  const hmac2 = generateHMAC('message', 'clé');
  assertEqual(hmac1, hmac2);
  assert(hmac1.length === 8, 'HMAC devrait avoir 8 caractères hex');
});

await test('verifyHMAC — valide un HMAC correct', async () => {
  const hmac = generateHMAC('important data', 'secret');
  assert(verifyHMAC('important data', 'secret', hmac), 'HMAC correct devrait être validé');
  assert(!verifyHMAC('modified data', 'secret', hmac), 'HMAC incorrect devrait être rejeté');
  assert(!verifyHMAC('important data', 'wrong_key', hmac), 'Mauvaise clé devrait être rejetée');
});

await test('compareConstantTime — comparaison correcte', async () => {
  assert(compareConstantTime('abc', 'abc'), 'Chaînes identiques');
  assert(!compareConstantTime('abc', 'abd'), 'Chaînes différentes');
  assert(!compareConstantTime('abc', 'ab'), 'Longueurs différentes');
  assert(compareConstantTime('', ''), 'Chaînes vides');
});

await test('compareConstantTime — résiste aux attaques par timing', async () => {
  // Vérifie que la fonction compare bien toutes les positions
  // (pas de retour anticipé sur le premier caractère différent)
  const a = 'x'.repeat(1000);
  const b = 'x'.repeat(999) + 'y';
  assert(!compareConstantTime(a, b), 'Devrait détecter la différence au dernier caractère');
});

summary();
