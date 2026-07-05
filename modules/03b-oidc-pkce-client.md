---
titre: "OAuth2 & OIDC côté client : Authorization Code + PKCE"
cours: 14-securite-applicative
notions: ["OAuth2 rôles (resource owner / client / AS / RS)", "grant types", "Authorization Code + PKCE", "client public vs confidentiel", "code_verifier / code_challenge (S256)", "id_token vs access_token", "state (anti-CSRF)", "nonce (anti-replay id_token)", "stockage de token (mémoire vs BFF)", "implicit flow déconseillé"]
outcomes:
  - sait nommer les 4 rôles OAuth2 et distinguer client public et client confidentiel
  - sait décrire le flux Authorization Code + PKCE étape par étape (challenge, code, échange)
  - sait distinguer id_token (authentification) et access_token (autorisation) et leur audience
  - sait justifier state, nonce et le choix de stockage de token pour un SPA
  - sait expliquer pourquoi l'implicit flow est déconseillé et remplacé par PKCE partout
prerequis: ["Modules 00-03 du cours (posture, OWASP, injection, authentification — sessions, JWT, authn vs authz)"]
next: 03c-webauthn-passkeys
libs: []
tribuzen: "Sécurité front-office TribuZen — connexion sociale / SSO (Google, Microsoft) via OIDC pour l'accès des parents à l'espace famille"
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# OAuth2 & OIDC côté client : Authorization Code + PKCE

> **Outcomes — tu sauras FAIRE :** décrire le flux Authorization Code + PKCE, distinguer `id_token` et `access_token`, justifier `state`/`nonce`/stockage de token, et expliquer pourquoi l'implicit flow est mort.
> **Difficulté :** :star::star::star:
>
> **Portée :** ce module traite le **client public (SPA / navigateur)**. La validation des tokens côté serveur, l'auth d'API et le JWT bien géré sont au **module 08**. Les passkeys (WebAuthn) sont au **module 03c**. On reste sur la **conception défensive du flux**, pas sur l'écriture d'un client OIDC de production (en vrai, on utilise une lib auditée).

## 1. Cas concret d'abord

TribuZen veut ajouter un bouton **« Se connecter avec Google »** pour les parents. Un stagiaire propose ce bout de code, copié d'un vieux tutoriel :

```js
// ❌ login-social.js — proposition à AUDITER (ne pas déployer)
function loginWithGoogle() {
  const params = new URLSearchParams({
    client_id: 'tribuzen-web',
    redirect_uri: 'https://app.tribuzen.fr/callback',
    response_type: 'token',        // ← renvoie l'access_token DANS l'URL
    scope: 'openid email profile',
  })
  // pas de state, pas de nonce, pas de PKCE
  window.location.href = `https://accounts.google.com/o/oauth2/v2/auth?${params}`
}

// au retour, on lit le token dans le fragment d'URL et on le range :
const token = new URLSearchParams(location.hash.slice(1)).get('access_token')
localStorage.setItem('access_token', token)   // ← stockage
```

**Quatre problèmes de sécurité, avant même de parler théorie :**

1. `response_type=token` = **implicit flow** : l'access_token transite dans l'URL (`#access_token=…`). Il finit dans l'historique du navigateur, les logs de proxy, le `Referer`. Ce flux est **déconseillé** (RFC 9700) et **supprimé d'OAuth 2.1**.
2. **Pas de PKCE** : rien ne prouve que c'est bien TribuZen qui a initié la demande — un code intercepté serait rejouable.
3. **Pas de `state`** : la page callback accepte n'importe quelle réponse → CSRF (on peut connecter la victime au compte de l'attaquant).
4. **`localStorage`** : toute faille XSS (module 02) lit le token et l'exfiltre. Aucune barrière.

Ce module remplace ce code par le flux **Authorization Code + PKCE**, seule approche recommandée aujourd'hui pour un client navigateur.

---

## 2. Théorie complète, concise

### 2.1 Les 4 rôles OAuth2 (RFC 6749)

OAuth2 est un protocole de **délégation d'autorisation** : donner à une app un accès limité à une ressource, sans lui donner le mot de passe.

| Rôle | Qui, dans TribuZen | Rôle |
|------|--------------------|------|
| **Resource Owner** | le parent | possède les données, consent à l'accès |
| **Client** | l'app TribuZen (SPA) | veut accéder aux données/identité |
| **Authorization Server (AS)** | Google / Microsoft Entra | authentifie le RO, émet les tokens |
| **Resource Server (RS)** | l'API TribuZen (ou l'API Google) | héberge les ressources, exige un access_token valide |

> OAuth2 = **autorisation** (« cette app peut-elle accéder à X ? »). Il ne dit rien de *qui* est l'utilisateur. C'est le rôle d'**OIDC** (OpenID Connect), une couche d'**authentification** posée sur OAuth2 (§2.5).

### 2.2 Client public vs client confidentiel

La distinction structure tout le reste :

- **Client confidentiel** : tourne sur un serveur que tu contrôles. Il peut garder un `client_secret`. Ex : un backend Node, un BFF.
- **Client public** : tourne chez l'utilisateur (SPA dans le navigateur, app mobile). **Il ne peut PAS garder de secret** — tout ce qui part au navigateur est lisible dans les DevTools. Un `client_secret` codé en dur dans un bundle JS n'est pas un secret.

Un SPA TribuZen est un **client public**. C'est précisément le cas que PKCE vient sécuriser.

### 2.3 Grant types (survol) et pourquoi Authorization Code gagne

| Grant type | Pour qui | Statut aujourd'hui |
|------------|----------|--------------------|
| **Authorization Code** (+ PKCE) | tous les clients (public et confidentiel) | **recommandé** |
| Implicit (`response_type=token`) | anciens SPA | **déconseillé** (RFC 9700), **retiré d'OAuth 2.1** |
| Resource Owner Password Credentials | (l'app saisit le mot de passe) | **déconseillé**, retiré d'OAuth 2.1 |
| Client Credentials | machine-à-machine (pas d'utilisateur) | ok, mais hors sujet client public |

RFC 9700 (Security BCP) est explicite : *« Although PKCE was designed as a mechanism to protect native apps, this advice applies to all kinds of OAuth clients, including web applications. »* → **Authorization Code + PKCE pour tout le monde.**

### 2.4 Le flux Authorization Code + PKCE, étape par étape

PKCE (*Proof Key for Code Exchange*, RFC 7636, prononcé « pixy ») ajoute une preuve dynamique à chaque demande. Le principe : le client génère un secret **éphémère** (`code_verifier`), n'en envoie que le **hash** (`code_challenge`) au départ, et ne révèle le secret qu'à l'échange final. Un attaquant qui intercepte le code d'autorisation ne peut pas l'échanger sans le `code_verifier`.

```
SPA (client public)          Authorization Server            API (RS)
 │                                   │                          │
 │ 1. code_verifier = random(43-128) │                          │
 │    code_challenge = S256(verifier)│                          │
 │    state = random, nonce = random │                          │
 │                                   │                          │
 │ 2. GET /authorize                 │                          │
 │    response_type=code             │                          │
 │    code_challenge, method=S256    │                          │
 │    state, nonce, scope=openid…    │                          │
 │──────────────────────────────────►│  (le parent se connecte  │
 │                                   │   et consent ici)         │
 │ 3. redirect vers redirect_uri     │                          │
 │◄────── ?code=…&state=… ───────────│                          │
 │                                   │                          │
 │ 4. vérifie state == celui envoyé  │                          │
 │                                   │                          │
 │ 5. POST /token                    │                          │
 │    grant_type=authorization_code  │                          │
 │    code + code_verifier (en clair)│                          │
 │──────────────────────────────────►│  AS recalcule            │
 │                                   │  S256(verifier)==challenge│
 │◄── id_token + access_token ───────│                          │
 │    (+ refresh_token éventuel)     │                          │
 │                                   │                          │
 │ 6. vérifie nonce dans id_token    │                          │
 │                                   │                          │
 │ 7. Authorization: Bearer <access> │                          │
 │──────────────────────────────────────────────────────────► │
```

Points **normatifs** à retenir (RFC 7636) :
- `code_verifier` : chaîne aléatoire à **haute entropie**, longueur **43 à 128** caractères, alphabet non réservé `[A-Z] [a-z] [0-9] - . _ ~`. La RFC recommande **≥ 256 bits d'entropie** (32 octets aléatoires).
- `code_challenge_method` : `plain` ou `S256`. *« If the client is capable of using S256, it MUST use S256. »* En pratique : toujours `S256`.
- Transformation S256 : `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`. À l'échange, l'AS revérifie `SHA256(code_verifier) == code_challenge`.

### 2.5 OIDC : id_token vs access_token

OIDC ajoute le scope `openid` et un nouveau token. **Ne jamais confondre les deux :**

| | `id_token` | `access_token` |
|---|-----------|----------------|
| Couche | OIDC (**authentification**) | OAuth2 (**autorisation**) |
| Répond à | *qui est l'utilisateur ?* | *cette app peut-elle appeler l'API ?* |
| Format | **toujours un JWT** signé, avec claims (`sub`, `email`, `iss`, `aud`, `exp`, `nonce`) | opaque **ou** JWT — au choix de l'AS |
| Audience (`aud`) | **le client** (TribuZen) | **le resource server** (l'API) |
| Destiné à | être lu/validé **par le client** | être présenté **au RS** en `Bearer` |
| Erreur classique | l'envoyer à l'API comme jeton d'accès | tenter d'en lire l'identité de l'utilisateur |

Règle : **l'`id_token` te dit qui s'est connecté ; l'`access_token` ouvre les portes de l'API.** Le client valide l'`id_token` (signature, `iss`, `aud`, `exp`, `nonce`) puis peut le jeter — l'`access_token` sert aux appels API suivants.

### 2.6 state et nonce : deux gardes distincts

- **`state`** : valeur aléatoire, liée à la session du navigateur, renvoyée telle quelle par l'AS. Au callback, le client **compare** : si `state` reçu ≠ `state` envoyé → rejet. Protège contre le **CSRF sur le callback** (empêche qu'on te fasse « atterrir » avec le code d'un attaquant).
- **`nonce`** (OIDC) : valeur aléatoire envoyée à `/authorize`, que l'AS **recopie dans l'`id_token`**. Le client vérifie que le `nonce` de l'`id_token` correspond. Protège contre le **rejeu d'un id_token** volé sur une autre session.

RFC 9700 : quand PKCE (ou le `nonce` OIDC) est en place, il fournit déjà une protection CSRF ; **sinon** un `state` à usage unique lié à l'agent utilisateur **doit** être utilisé. En pratique défensive : **PKCE + state + nonce**, ceinture et bretelles.

### 2.7 Stockage de token côté navigateur (le point sensible)

Aucun stockage navigateur n'est parfait — c'est un arbitrage. Le vrai risque de fond est le **XSS** (module 02) : si du JS attaquant s'exécute dans ta page, tout ce que le JS légitime peut lire, l'attaquant peut le lire.

| Emplacement | XSS peut le voler ? | Survit au refresh ? | Verdict |
|-------------|---------------------|---------------------|---------|
| `localStorage` / `sessionStorage` | **oui** (lecture JS directe) | oui | **à éviter pour les tokens** |
| Variable **en mémoire** (module JS) | difficile à exfiltrer en masse, perdu au refresh | non | acceptable pour l'access_token court |
| Cookie `HttpOnly` `Secure` `SameSite` | **non** (invisible au JS) | oui | bon — mais implique un serveur |
| **BFF** (Backend-For-Frontend) | tokens **jamais** dans le navigateur | oui (cookie de session) | **recommandé** pour app sensible |

Le BCP *OAuth 2.0 for Browser-Based Apps* **recommande fortement le pattern BFF** *« for business applications, sensitive applications, and applications that handle personal data »* — ce qui décrit exactement TribuZen (données de familles et d'enfants). Le BFF est un petit backend qui détient les tokens et n'expose au navigateur qu'un **cookie de session `HttpOnly`**. Le SPA n'a jamais l'access_token en main.

Si un BFF n'est pas possible : access_token **en mémoire uniquement**, jamais en `localStorage`, et surface XSS réduite au maximum. Et si des refresh tokens sont émis pour le navigateur, l'AS **doit** soit les faire **tourner à chaque usage (rotation)**, soit les **sender-constrain** (BCP browser-based apps).

---

## 3. Worked examples

### Exemple 1 — Reconstruire le flux TribuZen, défensif

On corrige le cas concret. Objectif : **Authorization Code + PKCE**, avec `state`, `nonce`, et stockage sûr. (Code illustratif ; en prod → lib auditée, cf. §4.)

```ts
// pkce.ts — génération conforme RFC 7636
function base64UrlEncode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function createPkcePair() {
  // 32 octets aléatoires ≈ 256 bits d'entropie (recommandation RFC)
  const verifierBytes = crypto.getRandomValues(new Uint8Array(32))
  const codeVerifier = base64UrlEncode(verifierBytes)          // 43 chars, alphabet non réservé
  const digest = await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(codeVerifier),
  )
  const codeChallenge = base64UrlEncode(new Uint8Array(digest)) // S256
  return { codeVerifier, codeChallenge }
}

function randomValue(): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)))
}
```

```ts
// login.ts — étape 1-2 : initier le flux
async function startLogin(cfg: OidcConfig) {
  const { codeVerifier, codeChallenge } = await createPkcePair()
  const state = randomValue()
  const nonce = randomValue()

  // le verifier et le state doivent survivre à la redirection, PAS localStorage.
  // sessionStorage = onglet courant, effacé à la fermeture ; acceptable ici
  // car ce sont des secrets ÉPHÉMÈRES, pas des tokens.
  sessionStorage.setItem('pkce_verifier', codeVerifier)
  sessionStorage.setItem('oauth_state', state)
  sessionStorage.setItem('oidc_nonce', nonce)

  const params = new URLSearchParams({
    response_type: 'code',                 // ✅ PAS 'token' — jamais d'implicit
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,         // doit matcher EXACTEMENT l'URI enregistrée
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })
  location.assign(`${cfg.authorizeEndpoint}?${params}`)
}
```

```ts
// callback.ts — étape 4-6 : vérifier et échanger
async function handleCallback(cfg: OidcConfig) {
  const q = new URLSearchParams(location.search)   // ✅ le code est dans la query, pas le fragment
  if (q.get('error')) throw new Error(`AS a refusé : ${q.get('error')}`)

  // 4. anti-CSRF : le state DOIT correspondre
  if (q.get('state') !== sessionStorage.getItem('oauth_state')) {
    throw new Error('state invalide — requête rejetée')
  }
  const code = q.get('code')
  const verifier = sessionStorage.getItem('pkce_verifier')
  if (!code || !verifier) throw new Error('flux incomplet')

  // secrets éphémères consommés → on les efface tout de suite
  sessionStorage.removeItem('pkce_verifier')
  sessionStorage.removeItem('oauth_state')

  // 5. échange code + code_verifier (aucun client_secret : client public)
  const res = await fetch(cfg.tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: cfg.redirectUri,
      client_id: cfg.clientId,
      code_verifier: verifier,             // ✅ la preuve PKCE
    }),
  })
  if (!res.ok) throw new Error('échange de token échoué')
  const tokens = await res.json() // { id_token, access_token, expires_in, ... }

  // 6. valider l'id_token : signature (via JWKS), iss, aud, exp — ET le nonce
  const claims = await verifyIdToken(tokens.id_token, cfg) // lib de vérif JWT
  if (claims.nonce !== sessionStorage.getItem('oidc_nonce')) {
    throw new Error('nonce invalide — id_token rejeté')
  }
  sessionStorage.removeItem('oidc_nonce')

  // 7. stockage : access_token EN MÉMOIRE seulement (jamais localStorage)
  tokenStore.setAccessToken(tokens.access_token, tokens.expires_in)
  return { user: claims.email }
}
```

Ce que la version corrigée neutralise : implicit → **code** ; interception de code → **PKCE** ; CSRF callback → **state** ; rejeu d'id_token → **nonce** ; vol XSS massif → **mémoire, pas localStorage**.

### Exemple 2 — Lire un id_token et décider où va chaque token

```ts
// id_token décodé (payload d'un JWT OIDC — exemple)
{
  "iss": "https://accounts.google.com",   // émetteur — à vérifier
  "aud": "tribuzen-web",                   // audience = LE CLIENT → c'est pour moi
  "sub": "108…42",                          // identifiant stable de l'utilisateur
  "email": "parent@example.com",
  "nonce": "9f3a…",                          // doit == nonce envoyé
  "exp": 1782000000
}
```

Décision :
- Cet **`id_token`** a `aud: "tribuzen-web"` (le client) → le SPA le **valide** pour savoir *qui* est connecté, puis peut l'oublier.
- Pour appeler `GET /api/families`, on envoie l'**`access_token`** (audience = l'API), pas l'id_token :

```ts
// ✅ correct
fetch('/api/families', {
  headers: { Authorization: `Bearer ${tokenStore.getAccessToken()}` },
})

// ❌ faux : envoyer l'id_token à l'API. Son audience est le client, pas le RS.
// L'API doit rejeter un token dont l'aud ne la désigne pas.
```

---

## 4. Pièges & misconceptions

### PIÈGE #1 — « PKCE, c'est juste pour le mobile »

Historiquement conçu pour les apps natives, mais **RFC 9700 l'étend à tous les clients, web inclus**. Public clients **MUST** use PKCE ; pour les clients confidentiels il est **RECOMMENDED**. OAuth 2.1 le rend **obligatoire pour tout usage d'Authorization Code**. Le correct : PKCE partout.

### PIÈGE #2 — « L'implicit flow, ça marche encore, c'est plus simple »

Il « marche » mais expose l'access_token dans l'URL (historique, logs, `Referer`) et n'a pas de preuve d'origine. RFC 9700 : *« Clients SHOULD NOT use the implicit grant. »* OAuth 2.1 le **retire** carrément. Le correct : `response_type=code` + PKCE, jamais `response_type=token`.

### PIÈGE #3 — Confondre id_token et access_token

L'`id_token` prouve **l'identité au client** (aud = client, toujours JWT). L'access_token ouvre **l'API** (aud = RS, opaque ou JWT). Envoyer l'id_token en `Bearer` à l'API, ou parser l'access_token pour en tirer l'identité, sont deux erreurs symétriques. Chaque token à sa destination.

### PIÈGE #4 — « state et nonce, c'est redondant »

Non : `state` protège le **callback** contre le CSRF (comparaison côté client) ; `nonce` protège l'**id_token** contre le rejeu (recopié par l'AS dans le token). Ils couvrent deux surfaces différentes. Défensif = les deux.

### PIÈGE #5 — Stocker les tokens dans `localStorage` « parce que c'est pratique »

`localStorage` est lisible par **tout** JS de la page : une seule faille XSS = tous les tokens exfiltrés, et ils survivent au refresh. Le correct : **BFF** (tokens hors navigateur) pour une app sensible comme TribuZen, sinon access_token **en mémoire**. Et `redirect_uri` en **exact string matching** côté AS (RFC 9700) — pas de wildcard.

### PIÈGE #6 — Implémenter le client OIDC soi-même en prod

Ce module te fait **comprendre** le flux pour l'auditer et le durcir. En production, on n'écrit pas la crypto et la validation JWT à la main : on utilise une **lib auditée** (ex. `oidc-client-ts` pour un SPA, ou la couche auth du framework, ou un provider géré). Réécrire from scratch = surface de bug. Comprendre ≠ réimplémenter.

---

## 5. Ancrage TribuZen

TribuZen ouvre l'espace famille aux parents via **connexion sociale / SSO** (Google, puis Microsoft Entra pour les familles en environnement pro). Enjeu réel : ce sont des **données de familles et d'enfants** — une fuite de token = accès à des informations sensibles de mineurs.

Décisions de conception retenues pour TribuZen :
- Flux **Authorization Code + PKCE**, `response_type=code`, `S256`. Jamais d'implicit.
- **Pattern BFF** : un petit service `auth-bff` détient les tokens ; le SPA ne reçoit qu'un cookie de session `HttpOnly` `Secure` `SameSite=Lax`. Aligné sur le BCP browser-based apps pour « applications handling personal data ».
- `state` **et** `nonce` systématiques ; `redirect_uri` en liste blanche exacte côté provider.
- Validation de l'`id_token` (signature via JWKS, `iss`, `aud`, `exp`, `nonce`) avant toute création de session.
- Refresh token (si présent) **jamais** exposé au navigateur — géré par le BFF, avec rotation.

```
tribuzen/
  apps/
    web/                       ← SPA : ne voit qu'un cookie de session, pas de token
    auth-bff/                  ← détient tokens OIDC, valide id_token, rotation refresh
  packages/
    auth/
      oidc-config.ts           ← endpoints, clientId, scopes (openid email profile)
```

> La **validation serveur** des access_tokens sur l'API TribuZen (audience, scopes, JWT bien géré) est détaillée au **module 08 — API security**. Ici on a sécurisé le **côté client / obtention** du token.

---

## 6. Points clés

1. OAuth2 = 4 rôles (resource owner, client, AS, RS) et fait de l'**autorisation** ; OIDC ajoute l'**authentification** (scope `openid`, `id_token`).
2. Un SPA est un **client public** : il ne peut pas garder de `client_secret`. PKCE remplace le secret par une preuve éphémère.
3. Flux recommandé pour tous : **Authorization Code + PKCE**, `response_type=code`, `code_challenge_method=S256`.
4. `code_verifier` : 43-128 caractères non réservés, ≥ 256 bits d'entropie ; `code_challenge = BASE64URL(SHA256(verifier))`.
5. `id_token` (aud = client, JWT, *qui*) ≠ `access_token` (aud = RS, *quoi accéder*) — chaque token à sa destination.
6. `state` protège le callback (CSRF) ; `nonce` protège l'id_token (rejeu). Les deux.
7. Tokens : **BFF** pour une app sensible, sinon **mémoire** ; jamais `localStorage`. `redirect_uri` en exact match.
8. **Implicit flow déconseillé** (RFC 9700) et **retiré d'OAuth 2.1** ; PKCE obligatoire partout.

---

## 7. Seeds Anki

```
Pourquoi un SPA ne peut-il pas utiliser de client_secret ?|C'est un client public : tout code envoyé au navigateur est lisible dans les DevTools. Un secret dans un bundle JS n'est pas secret. PKCE remplace le secret par une preuve éphémère (code_verifier).
Quelle est la transformation S256 de PKCE ?|code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier))). Le client envoie le challenge à /authorize et ne révèle le verifier qu'à l'échange /token ; l'AS revérifie le hash.
Contraintes du code_verifier (RFC 7636) ?|Chaîne aléatoire haute entropie, 43 à 128 caractères, alphabet non réservé [A-Z][a-z][0-9]-._~, avec au moins 256 bits d'entropie recommandés (32 octets aléatoires).
id_token vs access_token ?|id_token : authentification, toujours un JWT, audience = le client, dit QUI est l'utilisateur, validé par le client. access_token : autorisation, opaque ou JWT, audience = le resource server, présenté en Bearer à l'API.
À quoi servent state et nonce, et en quoi diffèrent-ils ?|state : comparé au callback pour bloquer le CSRF sur la redirection. nonce : recopié par l'AS dans l'id_token, vérifié par le client pour bloquer le rejeu d'id_token. Deux surfaces différentes.
Pourquoi l'implicit flow (response_type=token) est-il déconseillé ?|Il renvoie l'access_token dans l'URL (fragment) : fuite via historique, logs, Referer, et aucune preuve d'origine. RFC 9700 dit SHOULD NOT ; OAuth 2.1 le retire. Remplacé par Authorization Code + PKCE.
Où stocker les tokens dans un SPA sensible comme TribuZen ?|Idéalement pattern BFF : tokens côté serveur, le navigateur ne reçoit qu'un cookie de session HttpOnly. Sinon access_token en mémoire seulement. Jamais localStorage (lisible par tout XSS).
PKCE est-il réservé aux apps mobiles ?|Non. RFC 9700 l'étend à tous les clients, web inclus (public clients MUST, confidentiels RECOMMENDED). OAuth 2.1 le rend obligatoire pour tout usage d'Authorization Code.
```

---

## Pont vers le lab

> Lab associé : `labs/lab-03b-oidc-pkce-client/README.md`. Exercice **défensif** : auditer le flux social login du cas concret et le **re-concevoir** en Authorization Code + PKCE (state, nonce, stockage, redirect_uri) — pas de harnais, revue en session avec le coach.
