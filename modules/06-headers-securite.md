---
titre: En-têtes de sécurité HTTP — CSP, HSTS, cookies durcis, SRI
cours: 14-securite-applicative
notions: ["défense en profondeur côté navigateur", "'Content-Security-Policy' (CSP)", "directives CSP (default-src, script-src, frame-ancestors...)", "nonce vs hash vs 'unsafe-inline'", "CSP Report-Only + migration progressive", "'Strict-Transport-Security' (HSTS) + preload", "'X-Content-Type-Options: nosniff'", "clickjacking : X-Frame-Options vs frame-ancestors", "'Referrer-Policy'", "'Permissions-Policy'", "cookies Secure / HttpOnly / SameSite", "préfixes __Host- / __Secure-", "Subresource Integrity (SRI)", "helmet.js"]
outcomes:
  - "sait expliquer pourquoi les en-têtes de sécurité sont une couche de défense en profondeur côté navigateur, pas un substitut au code sûr"
  - "sait écrire une CSP stricte (default-src 'none', nonce plutôt que 'unsafe-inline') et la déployer en Report-Only avant de bloquer"
  - "sait configurer HSTS, X-Content-Type-Options, frame-ancestors, Referrer-Policy et Permissions-Policy avec des valeurs OWASP 2026"
  - "sait poser un cookie de session sûr (Secure, HttpOnly, SameSite, préfixe __Host-) et expliquer ce que chaque attribut protège"
  - "sait ajouter un hash SRI + crossorigin sur une ressource tierce et auditer les en-têtes d'une réponse"
prerequis:
  - "Introduction sécurité — défense en profondeur, modèle de menace (module 00)"
  - "OWASP Top 10 2021 — A05 Security Misconfiguration, A03 Injection/XSS (module 01)"
  - "Injection & XSS — pourquoi un script injecté est dangereux (module 02)"
  - "Authentification — cookie de session __Host-, HttpOnly (module 03)"
  - "Cryptographie — TLS/HTTPS, hachage SHA-256/384 (module 05)"
next: 07-cors
libs: []
tribuzen: front-office + API TribuZen — durcissement des en-têtes de sécurité HTTP servis au navigateur des familles
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# En-têtes de sécurité HTTP — CSP, HSTS, cookies durcis, SRI

> **Outcomes — tu sauras FAIRE :** écrire une CSP stricte et la déployer en Report-Only avant de bloquer, configurer HSTS / `nosniff` / `frame-ancestors` / Referrer-Policy / Permissions-Policy aux valeurs OWASP, poser un cookie de session `__Host-` sûr, et verrouiller une ressource tierce avec Subresource Integrity.
> **Difficulté :** :star::star::star:
>
> **Angle : DÉFENSIF.** On configure des barrières côté navigateur pour **durcir** TribuZen. On montre les attaques (XSS, clickjacking, MIME sniffing) seulement pour comprendre **ce que chaque en-tête bloque**, jamais pour attaquer un tiers.
>
> **Portée :** ce module couvre les **en-têtes de réponse de sécurité** et les **attributs de cookie**. Le partage cross-origin (`Access-Control-Allow-Origin`, preflight, `Cross-Origin-*`) est le **module 07 (CORS)** — on ne touche pas ici à `Access-Control-*`. Le protocole HTTP lui-même (cache, statuts, négociation) est le **cours 11**. Le TLS/HTTPS derrière HSTS est le **module 05 (cryptographie)**. Ici : quoi mettre dans les headers pour que le navigateur nous défende.

## 1. Cas concret d'abord

Tu reprends le serveur qui rend le front-office TribuZen (le tableau de bord où un parent gère les activités de ses enfants — **données de mineurs**). Un collègue a livré ce middleware Express. Il « marche » : la page s'affiche, la démo passe.

```typescript
// server.ts — AVANT durcissement. NE PAS livrer en prod.
import express from 'express'
const app = express()

app.get('/dashboard', (req, res) => {
  res.cookie('sid', sessionId)                 // (1) cookie de session nu
  res.send(`
    <html><body>
      <h1>Bonjour ${req.query.name}</h1>       <!-- (2) reflète l'entrée utilisateur -->
      <script src="https://cdn.tiers.example/widget.js"></script>  <!-- (3) script tiers non vérifié -->
      <script>initDashboard()</script>          <!-- (4) script inline -->
    </body></html>
  `)
})

app.listen(3000) // (5) sert en HTTP, pas de redirection HTTPS forcée
```

**Cinq portes ouvertes que ce module va fermer, toutes côté navigateur :**

1. **Cookie de session nu** — pas de `Secure` (transite en clair sur HTTP), pas de `HttpOnly` (un XSS le lit via `document.cookie`), pas de `SameSite` (envoyé sur des requêtes cross-site → CSRF). C'est le jeton d'identité d'un parent.
2. **XSS reflété** — `${req.query.name}` injecte du HTML non échappé. Une **CSP stricte** empêche un script injecté de s'exécuter, même si l'échappement a été oublié : c'est le filet de la défense en profondeur.
3. **Script tiers non vérifié** — si le CDN est compromis, `widget.js` s'exécute avec tous les droits de la page. **Subresource Integrity** refuse de charger le fichier s'il ne correspond pas au hash attendu.
4. **Script inline** — bloqué par une CSP stricte, sauf à autoriser `'unsafe-inline'` (à proscrire) ou à poser un **nonce**.
5. **Pas de HSTS** — le navigateur accepte le HTTP en clair ; un attaquant réseau peut intercepter ou downgrader. **HSTS** force le HTTPS pour toutes les visites suivantes.

À la fin du module, ce serveur pose un cookie `__Host-` `Secure`/`HttpOnly`/`SameSite`, envoie une CSP stricte à base de nonce, force HTTPS via HSTS, verrouille le script tiers par SRI, et neutralise MIME sniffing + clickjacking. C'est le fil rouge du lab.

---

## 2. Théorie complète, concise

### 2.1 Ce que sont (et ne sont pas) les en-têtes de sécurité

Un en-tête de sécurité est une **instruction envoyée au navigateur dans la réponse HTTP** : « n'exécute pas de script hors de cette liste », « n'affiche jamais cette page dans une iframe », « n'utilise que HTTPS ». Le navigateur applique la règle ; le serveur ne fait que la déclarer.

C'est de la **défense en profondeur** : une deuxième barrière **au cas où** le code primaire échoue. Une CSP ne remplace pas l'échappement anti-XSS ni la validation d'entrée (modules 02) — elle limite les dégâts quand ceux-ci ont une faille. Vérifié OWASP Secure Headers Project (2026-07) : ces en-têtes réduisent la surface d'attaque, ils ne corrigent pas une vuln applicative.

Réponse type d'une app durcie :

```http
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'none'; script-src 'self' 'nonce-r4nd0m'; ...
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Set-Cookie: __Host-sid=...; Secure; HttpOnly; SameSite=Lax; Path=/
```

### 2.2 Content-Security-Policy (CSP) — la pièce maîtresse

CSP contrôle **quelles ressources le navigateur a le droit de charger et d'exécuter**. C'est le principal rempart anti-XSS côté navigateur. Deux noms d'en-tête (vérifié MDN 2026-07) :

- `Content-Security-Policy` — **applique** (bloque les violations).
- `Content-Security-Policy-Report-Only` — **observe** (ne bloque pas, envoie un rapport). Sert à déployer sans casser.

**Directives principales** (vérifié MDN 2026-07) :

| Directive | Contrôle |
|---|---|
| `default-src` | fallback de toutes les directives `-src` non spécifiées |
| `script-src` | sources des scripts JS / WebAssembly |
| `style-src` | sources des feuilles de style |
| `img-src` | sources des images et favicons |
| `connect-src` | cibles de `fetch`, `XHR`, WebSocket |
| `font-src` | sources des polices `@font-face` |
| `frame-src` | sources des `<iframe>` imbriquées |
| `frame-ancestors` | qui a le droit d'**encadrer** cette page (anti-clickjacking) |
| `object-src` | sources de `<object>` / `<embed>` |
| `base-uri` | URLs autorisées dans `<base>` |
| `form-action` | cibles autorisées de `<form action>` |
| `upgrade-insecure-requests` | réécrit les URLs HTTP en HTTPS |

**Valeurs de source** (vérifié MDN 2026-07) — les mots-clés sont **entre apostrophes**, les schémas et hôtes non :

```
'self'           → même origine
'none'           → rien
'unsafe-inline'  → autorise scripts/styles inline (À ÉVITER)
'unsafe-eval'    → autorise eval() / new Function() (À ÉVITER)
'nonce-<valeur>' → autorise l'élément inline portant ce nonce
'sha256-<hash>'  → autorise l'inline dont le hash correspond (aussi sha384/sha512)
'strict-dynamic' → étend la confiance nonce/hash aux scripts qu'ils chargent
https:           → tout HTTPS
data:            → data URI (attention : img-src data: ok, script-src data: dangereux)
*.example.com    → sous-domaines
```

**CSP stricte de référence** — tout interdit par défaut, on ouvre au minimum :

```http
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'nonce-r4nd0m';
  style-src 'self';
  img-src 'self' data:;
  connect-src 'self' https://api.tribuzen.app;
  font-src 'self';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  upgrade-insecure-requests
```

`default-src 'none'` est une posture **deny-by-default** : rien ne charge tant qu'une directive explicite ne l'autorise pas. C'est l'inverse de `default-src 'self'`, plus permissif.

### 2.3 Inline : nonce et hash plutôt que `'unsafe-inline'`

Une CSP stricte **bloque les scripts inline** (`<script>...</script>` et `onclick="..."`) car un XSS injecte justement de l'inline. Deux façons d'autoriser **ton** inline légitime sans rouvrir la porte :

- **Nonce** — un jeton aléatoire **régénéré à chaque requête**, mis dans l'en-tête ET sur la balise. Le navigateur n'exécute que les scripts portant le bon nonce. Un attaquant ne peut pas deviner la valeur.

```typescript
import { randomBytes } from 'node:crypto'

app.use((req, res, next) => {
  const nonce = randomBytes(16).toString('base64') // NEUF à chaque requête
  res.locals.nonce = nonce
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'none'; script-src 'self' 'nonce-${nonce}'`,
  )
  next()
})
// dans le HTML : <script nonce="${res.locals.nonce}">initDashboard()</script>
```

> **Piège nonce** : un nonce fixe ou réutilisé ne vaut rien — l'attaquant le recopie. Il DOIT être imprévisible et régénéré par requête.

- **Hash** — pour un inline **statique** connu à l'avance : on met dans la CSP `'sha256-<hash du contenu exact du script, sans les balises>'`. Le navigateur hache l'inline trouvé et compare. Pas de génération par requête, mais il faut recalculer à chaque changement du script.

### 2.4 Déployer une CSP sans casser la prod : Report-Only + migration

Une CSP stricte plaquée d'un coup casse la moitié des pages. Migration en 4 temps :

1. **Report-Only** : `Content-Security-Policy-Report-Only` + une directive de reporting. Le navigateur **n'applique pas**, il **rapporte** les violations. On observe le trafic réel.
2. **Corriger** : externaliser les scripts inline, remplacer `'unsafe-inline'` par des nonces, lister les vraies sources.
3. **Basculer** en `Content-Security-Policy` (mode bloquant) quand les rapports sont propres.
4. **Resserrer** progressivement (`default-src 'self'` → `'none'`, retirer `https:` génériques).

Le reporting moderne (vérifié MDN 2026-07) : directive `report-to` dans la CSP + en-tête `Reporting-Endpoints` qui nomme l'URL. `report-uri` est l'ancienne forme, dépréciée mais encore reconnue — on met souvent les deux pour la compatibilité.

```http
Reporting-Endpoints: csp-endpoint="https://tribuzen.app/api/csp-report"
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /api/csp-report; report-to csp-endpoint
```

### 2.5 HSTS — forcer HTTPS

`Strict-Transport-Security` dit au navigateur : « pour ce domaine, n'utilise QUE HTTPS pendant `max-age` secondes, même si l'utilisateur tape `http://` ou clique un lien HTTP » (vérifié MDN 2026-07).

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

| Directive | Sens |
|---|---|
| `max-age=<s>` | **requis** — durée en secondes où le navigateur force HTTPS (63072000 = 2 ans) |
| `includeSubDomains` | applique aussi à tous les sous-domaines |
| `preload` | demande l'inscription dans la liste HSTS **intégrée aux navigateurs** |

**Preload** (hstspreload.org) : le domaine est en HTTPS **dès la première visite**, avant même toute réponse. Prérequis (vérifié MDN 2026-07) : `max-age ≥ 31536000` (1 an) **et** `includeSubDomains`. ⚠️ **Difficile à annuler** : n'inscris que si HTTPS marche parfaitement sur tous les sous-domaines. HSTS suppose un TLS valide (module 05).

### 2.6 nosniff, clickjacking, Referrer-Policy, Permissions-Policy

**`X-Content-Type-Options: nosniff`** (seule valeur valide) — empêche le navigateur de **deviner** le type MIME. Sans lui, un fichier servi en `text/plain` mais contenant du JS peut être interprété comme script. Toujours l'activer.

**Clickjacking** — un attaquant charge ta page dans une `<iframe>` invisible par-dessus la sienne pour piéger les clics. Deux parades (vérifié MDN 2026-07) :

- **`frame-ancestors` (CSP, moderne)** : `'none'` (personne), `'self'` (même origine), ou une liste d'origines. C'est le mécanisme à privilégier.
- **`X-Frame-Options` (ancien)** : `DENY` ou `SAMEORIGIN`. ⚠️ `ALLOW-FROM` est **obsolète** et ignoré par les navigateurs modernes → remplacé par `frame-ancestors`. On garde `X-Frame-Options: DENY` pour les vieux navigateurs, en doublon de `frame-ancestors 'none'`.

**`Referrer-Policy`** — contrôle ce que l'en-tête `Referer` divulgue en quittant ta page. Défaut navigateur depuis nov. 2020 (vérifié MDN 2026-07) : `strict-origin-when-cross-origin` — envoie l'URL complète en same-origin, seulement l'origine en cross-origin, **rien** vers une destination moins sûre (HTTPS→HTTP). C'est aussi la reco OWASP. À poser explicitement.

| Valeur | Comportement |
|---|---|
| `no-referrer` | aucun `Referer` |
| `same-origin` | URL complète en same-origin, rien en cross-origin |
| `strict-origin` | seulement l'origine, rien en downgrade HTTPS→HTTP |
| `strict-origin-when-cross-origin` | **défaut/reco** : complet en same-origin, origine en cross-origin, rien en downgrade |
| `unsafe-url` | URL complète partout — **fuite** d'info, à éviter |

**`Permissions-Policy`** (ex-`Feature-Policy`) — désactive les API navigateur non utilisées pour réduire la surface si un script hostile passe. Reco OWASP : couper caméra/micro/géoloc par défaut.

```http
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

`()` = liste d'origines vide = fonctionnalité coupée pour tous. `(self)` = autorisée pour l'origine ; `(self "https://maps.example.com")` = plus une origine tierce.

### 2.7 Cookies durcis — Secure, HttpOnly, SameSite, préfixes

Le cookie de session est le jeton d'identité : le durcir est non négociable (vérifié MDN 2026-07).

| Attribut | Protège de | Effet |
|---|---|---|
| `Secure` | interception réseau | cookie envoyé **uniquement en HTTPS** (sauf localhost) |
| `HttpOnly` | vol par XSS | **inaccessible à `document.cookie`** ; toujours envoyé par le navigateur |
| `SameSite=Lax` | CSRF | envoyé en same-site + navigation top-level GET ; **pas** sur POST cross-site ni sous-ressource |
| `SameSite=Strict` | CSRF (plus fort) | **jamais** en cross-site — même un lien entrant |
| `SameSite=None` | — | envoyé partout ; **exige `Secure`** (usage cross-site légitime seulement) |

**Préfixes de nom** (vérifié MDN 2026-07) — le navigateur **refuse** le cookie s'ils ne sont pas respectés :

- **`__Host-`** : exige `Secure`, posé depuis HTTPS, **`Path=/`**, et **aucun `Domain`** → le cookie est verrouillé sur l'hôte exact, pas partagé avec les sous-domaines. **Choix par défaut pour une session.**
- **`__Secure-`** : exige `Secure` et une origine HTTPS (plus permissif que `__Host-`).

```http
Set-Cookie: __Host-sid=<opaque>; Secure; HttpOnly; SameSite=Lax; Path=/
```

`HttpOnly` fait équipe avec la CSP : la CSP réduit le risque d'exécution d'un XSS, `HttpOnly` garantit qu'un XSS résiduel ne lit pas le cookie. Défense en profondeur.

### 2.8 Subresource Integrity (SRI) — verrouiller les ressources tierces

Charger un `<script>` depuis un CDN, c'est lui faire une confiance totale : s'il est compromis, son JS s'exécute avec les droits de ta page. **SRI** ajoute un **hash cryptographique attendu** : le navigateur télécharge, hache, et **refuse d'exécuter** si ça ne correspond pas (vérifié MDN 2026-07).

```html
<script
  src="https://cdn.tiers.example/widget.js"
  integrity="sha384-<hash base64 du fichier>"
  crossorigin="anonymous"></script>
```

- `integrity` : `algorithme-hashBase64`, algorithmes `sha256` / `sha384` / `sha512` (sha384+ recommandé). Plusieurs hashes séparés par une espace autorisés ; le navigateur retient le plus fort.
- `crossorigin="anonymous"` : **obligatoire** pour une ressource cross-origin — SRI exige une requête CORS ; sans lui, le chargement échoue même avec un hash valide.

Générer le hash : `openssl dgst -sha384 -binary widget.js | openssl base64 -A`, ou srihash.org. ⚠️ SRI protège l'**intégrité**, pas la disponibilité : si le CDN modifie le fichier (nouvelle version), le hash ne matche plus et le script ne charge plus — d'où l'usage de versions figées.

### 2.9 helmet.js — le point de départ

`helmet` pose une batterie d'en-têtes sains par défaut sur Express / NestJS. On part de là, puis on affine la CSP (helmet ne connaît pas tes sources).

```typescript
import helmet from 'helmet'

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      scriptSrc: ["'self'"],       // + nonce injecté par requête (voir §2.3)
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", 'https://api.tribuzen.app'],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
  hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  // helmet active nosniff et X-Frame-Options: SAMEORIGIN par défaut
}))
```

> OWASP recommande aussi de **retirer** les en-têtes qui divulguent la stack (`X-Powered-By`, `Server`) : `app.disable('x-powered-by')`. Le fingerprinting facilite le ciblage.

---

## 3. Worked examples

### Exemple 1 — Le serveur du §1, durci de bout en bout (TribuZen)

On reprend le middleware du cas concret et on ferme les cinq portes.

```typescript
// server.ts — APRÈS durcissement
import express from 'express'
import helmet from 'helmet'
import { randomBytes } from 'node:crypto'

const app = express()
app.disable('x-powered-by') // (bonus OWASP) ne pas divulguer la stack

// 1) Nonce neuf par requête + CSP stricte construite autour de ce nonce
app.use((req, res, next) => {
  res.locals.nonce = randomBytes(16).toString('base64')
  next()
})

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],                     // deny-by-default
        scriptSrc: [
          "'self'",
          (req, res) => `'nonce-${(res as any).locals.nonce}'`, // (4) autorise NOTRE inline
        ],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'", 'https://api.tribuzen.app'],
        frameAncestors: ["'none'"],                 // anti-clickjacking (CSP)
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }, // (5) force HTTPS
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    // nosniff + X-Frame-Options: SAMEORIGIN sont posés par défaut par helmet
  }),
)

app.get('/dashboard', (req, res) => {
  const nonce = res.locals.nonce

  // (1) Cookie de session durci : préfixe __Host- + Secure + HttpOnly + SameSite
  res.cookie('__Host-sid', sessionId, {
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    // pas de domain → exigence du préfixe __Host-
  })

  // (2) Échappement de l'entrée (la CSP est le FILET, pas l'excuse pour ne pas échapper)
  const safeName = escapeHtml(String(req.query.name ?? ''))

  res.send(`
    <html><body>
      <h1>Bonjour ${safeName}</h1>
      <!-- (3) SRI : le script tiers ne s'exécute que si son hash correspond -->
      <script
        src="https://cdn.tiers.example/widget.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w"
        crossorigin="anonymous"></script>
      <!-- (4) inline autorisé UNIQUEMENT par le nonce du jour -->
      <script nonce="${nonce}">initDashboard()</script>
    </body></html>
  `)
})
```

Ce qui a changé : CSP `default-src 'none'` + nonce (l'inline hostile ne s'exécute pas), SRI + `crossorigin` sur le CDN, HSTS, cookie `__Host-` `Secure`/`HttpOnly`/`SameSite`, `nosniff` et anti-clickjacking via helmet, `x-powered-by` retiré.

### Exemple 2 — Migration CSP en Report-Only, puis bascule

On ne plaque jamais une CSP stricte directement en prod. On observe d'abord.

```typescript
// Étape 1 — OBSERVER : Report-Only. Rien n'est bloqué, tout est rapporté.
app.use((req, res, next) => {
  res.setHeader('Reporting-Endpoints', 'csp-endpoint="https://tribuzen.app/api/csp-report"')
  res.setHeader(
    'Content-Security-Policy-Report-Only',
    "default-src 'self'; script-src 'self'; report-uri /api/csp-report; report-to csp-endpoint",
  )
  next()
})

// Endpoint qui collecte les violations pour savoir QUOI corriger avant de bloquer
app.post('/api/csp-report', express.json({ type: ['application/csp-report', 'application/json'] }), (req, res) => {
  const report = req.body['csp-report'] ?? req.body
  console.warn('[CSP]', {
    blocked: report['blocked-uri'],
    directive: report['violated-directive'],
    document: report['document-uri'],
  })
  res.status(204).end()
})

// Étape 2 (après avoir corrigé les violations remontées) — BLOQUER :
// on renomme l'en-tête Content-Security-Policy-Report-Only -> Content-Security-Policy
// et on resserre default-src 'self' -> 'none' quand les rapports sont vides.
```

Séquence : observer (Report-Only) → corriger les inline/sources signalés → basculer en bloquant → resserrer `'self'` vers `'none'`. Zéro interruption de service.

---

## 4. Pièges & misconceptions

### PIÈGE #1 — « Une CSP remplace l'échappement anti-XSS »
Faux. La CSP est un **filet de défense en profondeur**, pas un correctif. Un XSS mal échappé + une CSP permissive (`script-src 'unsafe-inline'`) = toujours exploitable. Correct : échapper les sorties (module 02) **ET** poser une CSP stricte. Les deux, pas l'un à la place de l'autre.

### PIÈGE #2 — Garder `'unsafe-inline'` « juste pour que ça marche »
`script-src 'unsafe-inline'` autorise **tout** script inline, y compris celui injecté par un attaquant : la CSP ne protège alors plus de rien contre le XSS. Correct : nonce (par requête) ou hash (statique). Note : `'nonce-...'` présent fait ignorer `'unsafe-inline'` par les navigateurs récents.

### PIÈGE #3 — Nonce fixe ou réutilisé
Un nonce codé en dur ou identique à chaque réponse est **recopiable** par l'attaquant → équivaut à `'unsafe-inline'`. Correct : `randomBytes` régénéré **à chaque requête**, jamais mis en cache.

### PIÈGE #4 — Cookie « Secure/HttpOnly » mais oublier `SameSite`
`Secure` + `HttpOnly` protègent de l'interception et du XSS, mais **pas du CSRF** : sans `SameSite`, le cookie part sur les requêtes cross-site. Correct : ajouter `SameSite=Lax` (ou `Strict` pour les actions sensibles). Et préférer le préfixe `__Host-`.

### PIÈGE #5 — `__Host-` avec un `Domain` ou sans `Path=/`
Le navigateur **rejette silencieusement** un cookie `__Host-` s'il a un attribut `Domain` ou s'il manque `Path=/`. Résultat : plus de session, bug déroutant. Correct : `__Host-name; Secure; Path=/` **sans** `Domain`.

### PIÈGE #6 — `X-Frame-Options: ALLOW-FROM` pour un partenaire
`ALLOW-FROM` est **obsolète** et **ignoré** par les navigateurs modernes → la page redevient encadrable. Correct : `Content-Security-Policy: frame-ancestors https://partenaire.example` (et `X-Frame-Options: DENY` en repli pour les vieux navigateurs quand aucun encadrement n'est voulu).

### PIÈGE #7 — SRI sans `crossorigin`
Un `<script integrity=...>` cross-origin **sans** `crossorigin="anonymous"` échoue à charger : SRI exige une requête CORS. Le hash seul ne suffit pas. Correct : toujours associer `integrity` et `crossorigin` sur une ressource tierce.

### PIÈGE #8 — HSTS `preload` posé trop tôt
`preload` inscrit le domaine dans une liste **intégrée aux navigateurs**, très **difficile à retirer**. Si un sous-domaine n'a pas HTTPS, il devient inaccessible. Correct : n'ajouter `preload` (et `includeSubDomains`) qu'une fois HTTPS certain partout ; tester avec un `max-age` court d'abord.

---

## 5. Ancrage TribuZen

TribuZen sert un front-office (tableau de bord familial) et une API. Les en-têtes se posent **une fois** dans le middleware du serveur qui répond au navigateur des familles — données de mineurs, durcissement obligatoire.

Où ça vit dans `smaurier/tribuzen` :

```
tribuzen-api/
  src/
    main.ts                    ← app.use(helmet(...)), app.disable('x-powered-by')
    security/
      csp.middleware.ts        ← nonce par requête + directives (default-src 'none')
      csp-report.controller.ts ← POST /api/csp-report (phase Report-Only)
    auth/
      session.config.ts        ← cookie __Host-sid : Secure/HttpOnly/SameSite=Lax/Path=/
tribuzen-web/
  index.html                   ← <script integrity="sha384-..." crossorigin> pour tout CDN
```

Points d'ancrage concrets :
- **CSP** : `default-src 'none'`, `script-src 'self' 'nonce-...'`, `connect-src 'self' https://api.tribuzen.app`, `frame-ancestors 'none'`. Déployée d'abord en **Report-Only**.
- **Cookie de session** : `__Host-sid` — cohérent avec le module 03 (authentification).
- **HSTS** : `max-age=63072000; includeSubDomains; preload` une fois HTTPS validé sur tous les sous-domaines.
- **SRI** sur toute ressource tierce du front (widgets, polices CDN).
- **CORS** (`Access-Control-Allow-Origin` pour l'API consommée par le web) → **module 07**, pas ici.

---

## 6. Points clés

1. Les en-têtes de sécurité sont une **défense en profondeur côté navigateur** : ils limitent les dégâts, ne remplacent pas le code sûr (échappement, validation).
2. **CSP** = principal rempart anti-XSS : viser `default-src 'none'`, ouvrir au minimum, autoriser l'inline par **nonce** (par requête) ou **hash**, jamais `'unsafe-inline'`.
3. Déployer une CSP en **`Content-Security-Policy-Report-Only`** d'abord (observer via `report-to`/`report-uri`), corriger, puis basculer en bloquant, puis resserrer.
4. **HSTS** (`max-age`, `includeSubDomains`, `preload`) force HTTPS ; `preload` est puissant mais **difficile à annuler** — seulement quand HTTPS est sûr partout.
5. `X-Content-Type-Options: nosniff` coupe le MIME sniffing ; **clickjacking** → `frame-ancestors 'none'` (moderne) + `X-Frame-Options: DENY` (repli), `ALLOW-FROM` étant obsolète.
6. `Referrer-Policy: strict-origin-when-cross-origin` (défaut/reco) et `Permissions-Policy: camera=(), microphone=(), geolocation=()` réduisent fuites et surface.
7. **Cookie de session** : `Secure` (HTTPS) + `HttpOnly` (anti-XSS) + `SameSite` (anti-CSRF) + préfixe **`__Host-`** (`Path=/`, sans `Domain`).
8. **SRI** (`integrity="sha384-..."` + `crossorigin="anonymous"`) verrouille l'intégrité d'une ressource tierce ; helmet.js est un bon point de départ, la CSP se peaufine ensuite.

---

## 7. Seeds Anki

```
En quoi une CSP est-elle une défense en profondeur et pas un correctif XSS ?|Elle limite ce que le navigateur exécute au cas où l'échappement échoue. Il faut TOUJOURS échapper les sorties (module 02) ET poser une CSP stricte — les deux, pas l'un à la place de l'autre.
Comment autoriser un script inline légitime sous une CSP stricte sans 'unsafe-inline' ?|Nonce (jeton aléatoire régénéré à CHAQUE requête, mis dans l'en-tête et sur la balise) ou hash 'sha256-/sha384-...' pour un inline statique. 'unsafe-inline' autoriserait aussi le script injecté.
Quelle est la séquence de déploiement d'une CSP sans casser la prod ?|1) Content-Security-Policy-Report-Only (observe, ne bloque pas) 2) corriger les violations remontées 3) basculer en Content-Security-Policy (bloquant) 4) resserrer default-src 'self' -> 'none'.
Que fait Strict-Transport-Security et quels sont les prérequis de preload ?|Force le navigateur à n'utiliser QUE HTTPS pour le domaine pendant max-age. preload (liste intégrée aux navigateurs, dès la 1re visite) exige max-age >= 31536000 ET includeSubDomains. Difficile à annuler.
Contre quoi protège chaque attribut d'un cookie de session Secure/HttpOnly/SameSite ?|Secure : interception (HTTPS uniquement). HttpOnly : vol par XSS (inaccessible à document.cookie). SameSite=Lax/Strict : CSRF (pas envoyé sur requêtes cross-site).
Quelles sont les exigences du préfixe de cookie __Host- ?|Attribut Secure, posé depuis HTTPS, Path=/ obligatoire, et AUCUN Domain. Le navigateur rejette le cookie sinon. Verrouille le cookie sur l'hôte exact.
Clickjacking : quelle est la parade moderne et pourquoi X-Frame-Options: ALLOW-FROM est-il à bannir ?|frame-ancestors 'none'/'self'/liste (CSP). ALLOW-FROM est obsolète et ignoré par les navigateurs modernes -> la page redevient encadrable. Garder X-Frame-Options: DENY en repli.
Pourquoi un <script integrity="sha384-..."> tiers a-t-il besoin de crossorigin="anonymous" ?|SRI exige une requête CORS pour la ressource cross-origin. Sans crossorigin, le chargement échoue même avec un hash valide. SRI protège l'intégrité (refuse si le hash ne matche pas), pas la disponibilité.
```

---

## Pont vers le lab

> Lab associé : `labs/lab-06-headers-securite/README.md`. Exercice **défensif** : durcir le serveur qui rend le front-office TribuZen — écrire une CSP stricte à base de nonce, la passer en Report-Only puis bloquant, poser un cookie `__Host-` sûr, ajouter HSTS/nosniff/frame-ancestors et un hash SRI, puis auditer les en-têtes. Vrai serveur, pas de harnais simulé. Corrigé commenté + variante J+30.
