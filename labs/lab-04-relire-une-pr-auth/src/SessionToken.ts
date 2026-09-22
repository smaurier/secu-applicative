// SessionToken.ts — L'EXISTANT, EN PRODUCTION. Une PR ouverte par un collègue, déjà
// mergée : signature et vérification de tokens de session "maison" (HMAC-SHA256). La démo
// passe : un token signé se vérifie, un token altéré est rejeté.
//
// AVANT toute chose : ouvre CE fichier — lui seul — et remplis `REVIEW.md` à la racine du
// lab.
//
// Contrat public à CONSERVER (les signatures ne changent pas) :
//   signSession(userId: string, expiresAt: number): string
//   verifySession(token: string): string | null — l'id utilisateur si le token est valide
//     ET non expiré, `null` sinon.
import { createHmac } from "node:crypto";

const SECRET = "tribuzen-secret-session-key";

function hmac(payload: string): string {
  return createHmac("sha256", SECRET).update(payload).digest("hex");
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
  if (sig !== expectedSig) return null;

  return userId;
}
