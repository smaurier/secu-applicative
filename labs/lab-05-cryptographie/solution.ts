import { createTestRunner } from '../test-utils.js';
const { test, assert, assertEqual, summary } = createTestRunner('Lab 05 — Cryptographie');

// ============================================================================
// Implémentations
// ============================================================================

function simpleHash(input: string): string {
  let hash = 0;
  for (const c of input) {
    hash = ((hash << 5) - hash + c.charCodeAt(0)) | 0;
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

function xorCipher(text: string, key: string): string {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    const xored = text.charCodeAt(i) ^ key.charCodeAt(i % key.length);
    result += xored.toString(16).padStart(2, '0');
  }
  return result;
}

function xorDecipher(hex: string, key: string): string {
  let result = '';
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.substring(i, i + 2), 16);
    const keyChar = key.charCodeAt((i / 2) % key.length);
    result += String.fromCharCode(byte ^ keyChar);
  }
  return result;
}

function base64Encode(input: string): string {
  return Buffer.from(input).toString('base64');
}

function base64Decode(encoded: string): string {
  return Buffer.from(encoded, 'base64').toString('utf-8');
}

function generateHMAC(message: string, key: string): string {
  return simpleHash(key + message + key);
}

function verifyHMAC(message: string, key: string, hmac: string): boolean {
  return generateHMAC(message, key) === hmac;
}

function compareConstantTime(a: string, b: string): boolean {
  if (a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
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
  const a = 'x'.repeat(1000);
  const b = 'x'.repeat(999) + 'y';
  assert(!compareConstantTime(a, b), 'Devrait détecter la différence au dernier caractère');
});

summary();
