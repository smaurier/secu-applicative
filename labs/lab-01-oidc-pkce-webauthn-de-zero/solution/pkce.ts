// pkce.ts — SOLUTION DE RÉFÉRENCE (commentée). Ne l'ouvre pas avant ton GREEN.
import { randomBytes, createHash } from "node:crypto";

function base64url(input: Buffer): string {
  return input.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function generateCodeVerifier(): string {
  // 32 octets aléatoires -> 43 caractères en base64url (sans padding), dans les bornes 43-128
  // de la RFC, et déjà dans l'alphabet autorisé (base64url = [A-Za-z0-9-_]).
  return base64url(randomBytes(32));
}

export function deriveCodeChallenge(verifier: string): string {
  return base64url(createHash("sha256").update(verifier).digest());
}
