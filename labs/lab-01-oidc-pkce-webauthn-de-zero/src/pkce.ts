// pkce.ts — PAGE BLANCHE. PKCE (Proof Key for Code Exchange, RFC 7636) : le mécanisme qui
// protège le flux OAuth2 Authorization Code pour un client PUBLIC (une SPA, une app
// mobile — qui ne peut pas garder de secret confidentiel). Le principe : le client prouve,
// au moment d'échanger le CODE contre un token, qu'il est bien celui qui a initié la
// demande — sans jamais transmettre de secret réutilisable en clair sur le canal
// intermédiaire (l'URL de redirection, visible dans l'historique du navigateur, les logs
// serveur, un referrer…).
//
// export function generateCodeVerifier(): string
//   - Une chaîne ALÉATOIRE (cryptographiquement sûre — `node:crypto`), 43 à 128 caractères,
//     composée UNIQUEMENT de [A-Za-z0-9-._~] (l'alphabet "unreserved" de la RFC 3986).
//   - Deux appels doivent renvoyer des valeurs DIFFÉRENTES (c'est un secret à usage unique).
//
// export function deriveCodeChallenge(verifier: string): string
//   - `BASE64URL(SHA256(verifier))`, SANS padding `=` (méthode "S256" de la RFC — jamais
//     "plain", qui n'apporte aucune protection).
//   - Vérifié contre l'exemple officiel de la RFC 7636 Annexe B (voir le test) : ce n'est
//     pas "à peu près la bonne formule", c'est LA formule exacte.
export function generateCodeVerifier(): string {
  throw new Error("generateCodeVerifier n'est pas encore implémenté");
}

export function deriveCodeChallenge(_verifier: string): string {
  throw new Error("deriveCodeChallenge n'est pas encore implémenté");
}
