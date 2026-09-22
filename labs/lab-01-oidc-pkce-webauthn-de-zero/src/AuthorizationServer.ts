// AuthorizationServer.ts — PAGE BLANCHE. Le CÔTÉ SERVEUR du flux PKCE : reçoit le
// `code_challenge` à l'autorisation, le stocke associé au `code` émis, puis vérifie à
// l'échange que le `code_verifier` présenté correspond VRAIMENT au challenge stocké —
// c'est cette vérification qui rend un `code` volé inutilisable sans le verifier d'origine.
//
// export class AuthorizationServer
//
//   beginAuthorization(codeChallenge: string): { code: string }
//     - Génère un `code` (chaîne aléatoire unique), l'associe au `codeChallenge` reçu,
//       le retourne. Un `code` déjà émis ne doit jamais être réutilisable en `code` de sortie
//       (deux appels → deux codes différents).
//
//   exchangeToken(code: string, codeVerifier: string): { accessToken: string }
//     - Retrouve le challenge associé à `code`. Si `code` est inconnu (jamais émis, ou déjà
//       consommé — UN SEUL échange par code) : lève `InvalidGrantError`.
//     - Recalcule `deriveCodeChallenge(codeVerifier)` (depuis `./pkce`) et le compare au
//       challenge stocké. Si ça ne correspond PAS : lève `PkceMismatchError` — NE JAMAIS
//       émettre de token dans ce cas, quelle que soit la validité du `code` par ailleurs.
//     - Si tout correspond : consomme le `code` (il devient invalide pour un futur appel,
//       même avec le bon verifier) et retourne un `{ accessToken }` (chaîne aléatoire).
import { deriveCodeChallenge } from "./pkce";

export class InvalidGrantError extends Error {}
export class PkceMismatchError extends Error {}

export class AuthorizationServer {
  beginAuthorization(_codeChallenge: string): { code: string } {
    throw new Error("beginAuthorization n'est pas encore implémenté");
  }

  exchangeToken(_code: string, _codeVerifier: string): { accessToken: string } {
    throw new Error("exchangeToken n'est pas encore implémenté");
  }
}
