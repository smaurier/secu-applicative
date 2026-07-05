<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Lab 03b — Auditer et durcir un flux OIDC (Authorization Code + PKCE)

> **Outcome :** à la fin, tu sais **auditer** un flux de connexion sociale vulnérable et le **re-concevoir** en Authorization Code + PKCE, en justifiant chaque garde (`state`, `nonce`, `code_challenge`, stockage de token, `redirect_uri`).
> **Vrai outil :** un vrai provider OIDC de test (**Google Cloud OAuth**, **Auth0 free**, ou **Keycloak** en local via Docker) + le navigateur (onglet Réseau des DevTools pour observer `/authorize` et `/token`). Aucune lib d'attaque, aucun système tiers ciblé — tu durcis **ta propre** app.
> **Feedback :** le coach valide ta conception et ton audit en session — pas de test-runner auto-correcteur.

Ce lab est **défensif** : on part d'un code faible fourni, on **explique pourquoi il est dangereux**, et on **construit la version durcie**. On n'écrit aucun exploit et on n'attaque aucun service qu'on ne possède pas.

---

## Énoncé

TribuZen ajoute « Se connecter avec Google » pour les parents. Voici la proposition à **auditer puis remplacer** (c'est le cas concret du module) :

```js
// login-social.js — À AUDITER (ne pas déployer)
function loginWithGoogle() {
  const params = new URLSearchParams({
    client_id: 'tribuzen-web',
    redirect_uri: 'https://app.tribuzen.fr/callback',
    response_type: 'token',
    scope: 'openid email profile',
  })
  window.location.href = `https://accounts.google.com/o/oauth2/v2/auth?${params}`
}

// au retour :
const token = new URLSearchParams(location.hash.slice(1)).get('access_token')
localStorage.setItem('access_token', token)
```

**Ton livrable en deux parties :**

### Partie A — Rapport d'audit (écrit, ~1 page)

Pour **chacune** des 4 faiblesses ci-dessous : nomme-la, explique l'impact concret pour TribuZen (données de familles/enfants), et cite la garde qui la corrige.

1. `response_type=token` (implicit flow).
2. Absence de PKCE.
3. Absence de `state`.
4. `localStorage` pour l'access_token.

Ajoute une 5ᵉ ligne : que doit vérifier le **provider** sur `redirect_uri` ?

### Partie B — Conception durcie

Réécris le flux en **Authorization Code + PKCE**. Tu dois produire, en TypeScript (pseudo-réel, pas besoin de builder une app complète) :

- `createPkcePair()` — `code_verifier` conforme RFC 7636 (43-128 chars, ≥ 256 bits) + `code_challenge` en `S256` via Web Crypto.
- `startLogin()` — construit l'URL `/authorize` avec `response_type=code`, `code_challenge`, `state`, `nonce`, `scope=openid email profile`, et **persiste** verifier/state/nonce de façon appropriée (pas dans `localStorage`).
- `handleCallback()` — vérifie `state`, échange `code` + `code_verifier` sur `/token`, valide le `nonce` de l'`id_token`, et range l'access_token **hors `localStorage`**.
- Un court paragraphe : **où** iront les tokens dans TribuZen (mémoire vs BFF) et **pourquoi**.

**Validation réelle :** configure un client OIDC de test (Google/Auth0/Keycloak) en **client public / SPA**, avec un `redirect_uri` exact (ex. `http://localhost:5173/callback`). Lance ton `startLogin()` et observe dans l'onglet **Réseau** : la requête `/authorize` contient bien `response_type=code` et `code_challenge`, et la réponse `/token` renvoie un `id_token`. C'est ton oracle : le provider **refuse** le flux si PKCE est mal formé.

---

## Étapes (en friction)

1. **Audit d'abord, code ensuite.** Rédige la Partie A **sans** regarder le corrigé. Pour chaque faiblesse, écris une phrase « impact » et une phrase « correction ».
2. **Provider de test.** Crée un client OIDC (Google Cloud Console → *OAuth client ID* type *Web application*, ou Auth0 *Single Page Application*, ou Keycloak Docker). Note `clientId`, `authorizeEndpoint`, `tokenEndpoint`, et **enregistre le `redirect_uri` exact**.
3. **PKCE.** Écris `createPkcePair()`. Vérifie à la main : `codeVerifier.length >= 43`, alphabet non réservé, `codeChallenge` en base64url sans `=`.
4. **startLogin.** Construis l'URL. **Réfléchis** : où stocker `code_verifier`/`state`/`nonce` le temps de la redirection ? (ce sont des secrets **éphémères**, pas des tokens — justifie ton choix).
5. **handleCallback.** Vérifie `state` **avant** tout. Échange le code. Valide le `nonce`. Range l'access_token hors `localStorage`.
6. **Observe le réseau.** Dans DevTools → Réseau, confirme `response_type=code` + `code_challenge_method=S256` sur `/authorize`, et un `id_token` dans la réponse `/token`.
7. **Décision de stockage.** Écris ta recommandation TribuZen (BFF vs mémoire) et défends-la face à une objection « mais localStorage c'est plus simple ».

---

## Corrigé complet commenté

### Partie A — repères d'audit attendus

| Faiblesse | Impact TribuZen | Correction |
|-----------|-----------------|------------|
| `response_type=token` (implicit) | access_token dans l'URL → historique, logs, `Referer` ; un token d'accès aux données famille fuite passivement. Déconseillé RFC 9700, retiré OAuth 2.1. | `response_type=code` + PKCE |
| Pas de PKCE | un code d'autorisation intercepté est rejouable ; rien ne prouve que c'est TribuZen qui a initié. | `code_challenge`/`code_verifier` S256 |
| Pas de `state` | CSRF sur le callback : on peut connecter un parent au compte d'un attaquant (ou l'inverse). | `state` aléatoire, comparé au retour |
| `localStorage` | toute faille XSS lit et exfiltre le token, qui survit au refresh. | mémoire, ou BFF (cookie `HttpOnly`) |
| `redirect_uri` | si le provider accepte des wildcards, un code peut être redirigé vers un domaine attaquant. | exact string matching côté provider (RFC 9700) |

### Partie B — conception durcie

```ts
// pkce.ts
function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function createPkcePair() {
  // 32 octets ≈ 256 bits d'entropie (recommandation RFC 7636)
  const verifier = base64Url(crypto.getRandomValues(new Uint8Array(32)))
  // → 43 caractères, alphabet non réservé : conforme
  const digest = await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(verifier),
  )
  // S256 obligatoire dès que le client en est capable (RFC 7636)
  const challenge = base64Url(new Uint8Array(digest))
  return { verifier, challenge }
}

export function randomValue(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(16)))
}
```

```ts
// login.ts
interface OidcConfig {
  clientId: string
  redirectUri: string        // DOIT matcher exactement l'URI enregistrée côté provider
  authorizeEndpoint: string
  tokenEndpoint: string
}

export async function startLogin(cfg: OidcConfig) {
  const { verifier, challenge } = await createPkcePair()
  const state = randomValue()
  const nonce = randomValue()

  // Secrets ÉPHÉMÈRES (pas des tokens) : ils doivent survivre à la redirection
  // vers le provider et revenir. sessionStorage = onglet courant, effacé à la
  // fermeture. Acceptable ici PARCE QUE ce ne sont pas des tokens d'accès et
  // qu'ils sont consommés une seule fois au callback. On ne met JAMAIS de token là.
  sessionStorage.setItem('pkce_verifier', verifier)
  sessionStorage.setItem('oauth_state', state)
  sessionStorage.setItem('oidc_nonce', nonce)

  const params = new URLSearchParams({
    response_type: 'code',              // ✅ jamais 'token'
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  })
  location.assign(`${cfg.authorizeEndpoint}?${params}`)
}
```

```ts
// callback.ts
export async function handleCallback(cfg: OidcConfig) {
  const q = new URLSearchParams(location.search) // code dans la QUERY, pas le fragment
  if (q.get('error')) throw new Error(`provider a refusé : ${q.get('error')}`)

  // 1) anti-CSRF AVANT tout traitement
  if (q.get('state') !== sessionStorage.getItem('oauth_state')) {
    throw new Error('state invalide — requête rejetée')
  }

  const code = q.get('code')
  const verifier = sessionStorage.getItem('pkce_verifier')
  if (!code || !verifier) throw new Error('flux incomplet')

  // secrets consommés → effacés immédiatement
  sessionStorage.removeItem('pkce_verifier')
  sessionStorage.removeItem('oauth_state')

  // 2) échange code + code_verifier (aucun client_secret : client public)
  const res = await fetch(cfg.tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: cfg.redirectUri,
      client_id: cfg.clientId,
      code_verifier: verifier,           // ✅ preuve PKCE
    }),
  })
  if (!res.ok) throw new Error('échange de token échoué')
  const tokens = await res.json() as {
    id_token: string; access_token: string; expires_in: number
  }

  // 3) valider l'id_token : signature (JWKS), iss, aud, exp — puis le nonce.
  //    En prod on utilise une lib de vérif JWT ; ici on illustre le nonce.
  const claims = await verifyIdToken(tokens.id_token, cfg)
  if (claims.nonce !== sessionStorage.getItem('oidc_nonce')) {
    throw new Error('nonce invalide — id_token rejeté')
  }
  sessionStorage.removeItem('oidc_nonce')

  // 4) stockage : access_token EN MÉMOIRE (jamais localStorage)
  tokenStore.setAccessToken(tokens.access_token, tokens.expires_in)
  return { email: claims.email }
}
```

**Recommandation de stockage TribuZen (paragraphe attendu) :**

> TribuZen manipule des données de familles et d'enfants → cible le **pattern BFF** : un service `auth-bff` détient les tokens et n'expose au SPA qu'un cookie de session `HttpOnly` `Secure` `SameSite`. Le navigateur n'a alors **aucun** token à voler, même en cas de XSS. Tant que le BFF n'est pas en place, l'access_token reste **en mémoire** (variable de module, perdue au refresh) et **jamais** en `localStorage`. Réponse à « localStorage c'est plus simple » : simple, mais une seule faille XSS = exfiltration de tous les tokens, persistants au refresh — inacceptable pour des données de mineurs.

**Pourquoi ce corrigé est correct :**
- `response_type=code` + PKCE `S256` : le code seul ne suffit pas, il faut le `code_verifier` détenu uniquement par l'onglet initiateur.
- `state` vérifié **en premier** au callback : bloque le CSRF avant tout échange.
- `nonce` recopié dans l'`id_token` et revalidé : bloque le rejeu d'un id_token capté ailleurs.
- Secrets éphémères en `sessionStorage`, **tokens** hors de `localStorage` : la surface de vol est minimisée.
- `redirect_uri` exact côté provider : pas de détournement du code vers un domaine tiers.

---

## Variante J+30 (fading)

Reprends l'exercice **de mémoire, en 30 minutes**, sans rouvrir ce corrigé ni le module, avec **une contrainte ajoutée** :

- Le provider émet aussi un **refresh_token** pour le navigateur. Décris (et code le squelette) la façon **sûre** de le gérer : pourquoi il ne doit **pas** vivre dans le SPA, comment le **BFF** le détient, et ce que l'AS **doit** faire à chaque usage (**rotation** des refresh tokens ou sender-constraining, cf. BCP browser-based apps).

**Critère de réussite :** tu expliques sans notes pourquoi l'access_token va en mémoire, le refresh_token dans le BFF, et tu cites rotation OU sender-constrained comme exigence.

---

## Application TribuZen

Dans le repo `smaurier/tribuzen` :

```
tribuzen/
  apps/
    web/                       ← SPA : ne détient qu'un cookie de session
    auth-bff/                  ← détient tokens OIDC, valide id_token, rotation refresh
  packages/
    auth/
      pkce.ts                  ← createPkcePair (Partie B)
      oidc-config.ts           ← endpoints, clientId, scopes
```

**Différences avec le lab :**
- En prod, la **validation de l'id_token** (signature via JWKS, `iss`, `aud`, `exp`) passe par une **lib auditée**, pas du code maison.
- Le flux réel s'appuie sur `oidc-client-ts` (SPA) ou la couche auth du framework + le **BFF** — tu ne réécris pas la crypto.
- La **validation des access_tokens côté API** (audience, scopes) est traitée au **module 08**.

**Commit cible :**
```
feat(auth): social login OIDC — Authorization Code + PKCE, state/nonce, tokens via BFF
```
