// SessionToken.ts — SOLUTION DE RÉFÉRENCE (commentée). Ne l'ouvre pas avant ton GREEN.
import { createHmac, timingSafeEqual } from "node:crypto";

const SECRET = "tribuzen-secret-session-key";

function hmac(payload: string): string {
  return createHmac("sha256", SECRET).update(payload).digest("hex");
}

function timingSafeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  // Comparer la LONGUEUR avant timingSafeEqual est sûr : la longueur d'une signature
  // HMAC-SHA256 est fixe et publique, ce n'est pas une fuite d'information exploitable.
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

export function signSession(userId: string, expiresAt: number): string {
  const payload = `${userId}.${expiresAt}`;
  return `${payload}.${hmac(payload)}`;
}

export function verifySession(token: string): string | null {
  const [userId, expiresAtStr, sig] = token.split(".");
  if (!userId || !expiresAtStr || !sig) return null;

  const payload = `${userId}.${expiresAtStr}`;
  const expectedSig = hmac(payload);
  // Comparaison à temps constant : `!==` sur deux chaînes s'arrête au premier caractère
  // différent, ce qui fuit (en théorie, mesurable sur un service réseau) combien de
  // caractères du début sont corrects — une porte d'entrée pour deviner la signature octet
  // par octet.
  if (!timingSafeStringEqual(sig, expectedSig)) return null;

  const expiresAt = Number(expiresAtStr);
  if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) return null;

  return userId;
}
