// buildCsp.ts — PAGE BLANCHE. Écris une Content-Security-Policy STRICTE pour le front
// TribuZen EXISTANT (voir l'inventaire des ressources ci-dessous — RIEN de cet inventaire ne
// doit être cassé par ta politique) — sans jamais recourir à `unsafe-inline`/`unsafe-eval`,
// le trou qui annule presque tout l'intérêt d'une CSP contre le XSS.
//
// Inventaire du front EXISTANT (à ne pas casser) :
//   - Scripts : 'self', plus une lib tierce chargée depuis https://cdn.jsdelivr.net, PLUS un
//     <script> INLINE de bootstrap (pose window.__ENV__ avant le bundle principal) — ce
//     script inline doit passer par un NONCE, jamais par 'unsafe-inline'.
//   - Styles : 'self' uniquement (pas de style inline dans ce front).
//   - Images : 'self', plus https://images.tribuzen.app (avatars, illustrations).
//   - Connexions réseau (fetch/XHR) : 'self', plus https://api.tribuzen.app.
//
// export function buildCsp(nonce: string): string
//   - Retourne l'en-tête complet, directives séparées par "; " (avec un espace).
//   - `script-src` DOIT contenir 'self', l'origine CDN, ET `'nonce-<nonce>'` — le nonce REÇU
//     en paramètre, pas une valeur fixe (deux appels avec des nonces différents doivent
//     produire des en-têtes différents).
//   - AUCUNE directive ne doit contenir `unsafe-inline` ni `unsafe-eval`.
//   - `object-src 'none'` (bloque les plugins/Flash, best practice indépendante du reste).
//   - `base-uri 'self'` (empêche l'injection d'un <base> qui détournerait des URLs relatives).
export function buildCsp(_nonce: string): string {
  throw new Error("buildCsp n'est pas encore implémenté");
}
