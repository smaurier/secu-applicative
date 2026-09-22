// Oracle de NON-RÉGRESSION. Ne pas modifier. Passe déjà sur l'existant — signer puis vérifier
// un token frais fonctionne, un token altéré est rejeté.
import { describe, expect, it } from "vitest";
import { signSession, verifySession } from "@lab/SessionToken";

describe("SessionToken — non-régression", () => {
  it("un token fraîchement signé se vérifie et renvoie le bon userId", () => {
    const token = signSession("user-42", Date.now() + 60_000);
    expect(verifySession(token)).toBe("user-42");
  });

  it("un token dont l'userId a été altéré (signature invalide) est rejeté", () => {
    const token = signSession("user-42", Date.now() + 60_000);
    const [, expiresAt, sig] = token.split(".");
    const tokenAltere = `user-99.${expiresAt}.${sig}`;
    expect(verifySession(tokenAltere)).toBeNull();
  });

  it("un token malformé (pas assez de segments) est rejeté", () => {
    expect(verifySession("n-importe-quoi")).toBeNull();
  });
});
