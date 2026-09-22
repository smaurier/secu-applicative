// Oracle du lab 01 sécurité. Ne pas modifier. PKCE en entier : génération, dérivation
// (vérifiée contre le vecteur de test OFFICIEL de la RFC 7636 Annexe B), et les deux
// propriétés de sécurité qui sont la RAISON D'ÊTRE du mécanisme.
import { describe, expect, it } from "vitest";
import { deriveCodeChallenge, generateCodeVerifier } from "@lab/pkce";
import { AuthorizationServer, InvalidGrantError, PkceMismatchError } from "@lab/AuthorizationServer";

describe("generateCodeVerifier — aléatoire, conforme RFC 7636 (longueur, alphabet)", () => {
  it("longueur entre 43 et 128 caractères", () => {
    const v = generateCodeVerifier();
    expect(v.length).toBeGreaterThanOrEqual(43);
    expect(v.length).toBeLessThanOrEqual(128);
  });

  it("n'utilise que l'alphabet autorisé [A-Za-z0-9-._~]", () => {
    expect(generateCodeVerifier()).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  it("deux appels renvoient des valeurs différentes (un vrai secret, pas une constante)", () => {
    expect(generateCodeVerifier()).not.toBe(generateCodeVerifier());
  });
});

describe("deriveCodeChallenge — vecteur de test OFFICIEL, RFC 7636 Annexe B", () => {
  it("reproduit exactement l'exemple publié par la RFC", () => {
    const verifierRFC = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const challengeAttendu = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    expect(deriveCodeChallenge(verifierRFC)).toBe(challengeAttendu);
  });
});

describe("AuthorizationServer — le flux complet, et les deux propriétés de sécurité", () => {
  it("flux nominal : verifier -> challenge -> code -> token", () => {
    const verifier = generateCodeVerifier();
    const challenge = deriveCodeChallenge(verifier);
    const server = new AuthorizationServer();

    const { code } = server.beginAuthorization(challenge);
    const { accessToken } = server.exchangeToken(code, verifier);

    expect(typeof accessToken).toBe("string");
    expect(accessToken.length).toBeGreaterThan(0);
  });

  it("SÉCURITÉ 1 — un code volé est inutilisable sans le BON verifier", () => {
    const verifier = generateCodeVerifier();
    const challenge = deriveCodeChallenge(verifier);
    const server = new AuthorizationServer();
    const { code } = server.beginAuthorization(challenge);

    const mauvaisVerifier = generateCodeVerifier(); // l'attaquant ne connaît QUE le code
    expect(() => server.exchangeToken(code, mauvaisVerifier)).toThrow(PkceMismatchError);
  });

  it("SÉCURITÉ 2 — un code est à USAGE UNIQUE (rejeu impossible, même avec le bon verifier)", () => {
    const verifier = generateCodeVerifier();
    const challenge = deriveCodeChallenge(verifier);
    const server = new AuthorizationServer();
    const { code } = server.beginAuthorization(challenge);

    server.exchangeToken(code, verifier); // premier échange, légitime
    expect(() => server.exchangeToken(code, verifier)).toThrow(InvalidGrantError);
  });

  it("un code jamais émis est rejeté", () => {
    const server = new AuthorizationServer();
    expect(() => server.exchangeToken("code-inexistant", generateCodeVerifier())).toThrow(InvalidGrantError);
  });
});
