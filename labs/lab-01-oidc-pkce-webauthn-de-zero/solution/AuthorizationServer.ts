// AuthorizationServer.ts — SOLUTION DE RÉFÉRENCE (commentée). Ne l'ouvre pas avant ton GREEN.
import { randomBytes } from "node:crypto";
import { deriveCodeChallenge } from "./pkce";

export class InvalidGrantError extends Error {}
export class PkceMismatchError extends Error {}

interface CodeRecord {
  codeChallenge: string;
  consumed: boolean;
}

export class AuthorizationServer {
  private readonly codes = new Map<string, CodeRecord>();

  beginAuthorization(codeChallenge: string): { code: string } {
    const code = randomBytes(16).toString("hex");
    this.codes.set(code, { codeChallenge, consumed: false });
    return { code };
  }

  exchangeToken(code: string, codeVerifier: string): { accessToken: string } {
    const record = this.codes.get(code);
    if (!record || record.consumed) {
      throw new InvalidGrantError(`Code ${code} inconnu ou déjà consommé.`);
    }

    if (deriveCodeChallenge(codeVerifier) !== record.codeChallenge) {
      // On ne consomme PAS le code sur un échec : un attaquant qui tente plusieurs verifiers
      // au hasard ne doit pas pouvoir "user" le vrai flux en le grillant accidentellement.
      throw new PkceMismatchError("Le code_verifier ne correspond pas au code_challenge.");
    }

    record.consumed = true;
    return { accessToken: randomBytes(32).toString("hex") };
  }
}
