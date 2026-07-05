<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Lab 06 — Durcir les en-têtes de sécurité de TribuZen

> **Outcome :** à la fin, tu sais durcir un vrai serveur Express qui rend le front-office TribuZen — CSP stricte à base de nonce (Report-Only puis bloquant), cookie de session `__Host-`, HSTS, `nosniff`, anti-clickjacking et un hash SRI — puis auditer les en-têtes de la réponse.
> **Vrai outil :** Node.js + Express + `helmet`, observé avec `curl -I` et l'onglet Réseau du navigateur (les DevTools montrent l'en-tête `Content-Security-Policy` et les violations en console).
> **Feedback :** le coach valide en session à partir de la grille ci-dessous — pas de test-runner auto-correcteur.
>
> **Angle : DÉFENSIF.** Tu **durcis TON propre serveur** local. Aucune cible tierce, aucun payload d'attaque contre un système externe. On observe ce que chaque en-tête bloque sur ta propre page.

---

## Énoncé

Voici le serveur `server.ts` livré par un collègue. Il rend le tableau de bord d'un parent (données de mineurs) et il « marche » en démo — mais il n'a **aucun** en-tête de sécurité, un cookie de session nu, un script tiers non vérifié et un XSS reflété.

**Ta mission : le durcir sans casser l'affichage.** Tu produis le serveur complet ; pas de gap-fill.

### Starter (à copier tel quel, puis à durcir)

```typescript
// server.ts — starter VULNÉRABLE. À durcir dans ce lab.
import express from 'express'

const app = express()
const sessionId = 'demo-session-123' // en vrai : généré à la connexion (module 03)

app.get('/dashboard', (req, res) => {
  // Cookie de session nu : ni Secure, ni HttpOnly, ni SameSite
  res.cookie('sid', sessionId)

  // Entrée utilisateur reflétée sans échappement (XSS reflété)
  const name = String(req.query.name ?? 'famille')

  res.send(`
    <html><body>
      <h1>Bonjour ${name}</h1>
      <!-- script tiers sans vérification d'intégrité -->
      <script src="https://cdn.jsdelivr.net/npm/canvas-confetti@1.9.3/dist/confetti.browser.min.js"></script>
      <!-- script inline -->
      <script>console.log('dashboard prêt')</script>
    </body></html>
  `)
})

app.listen(3000, () => console.log('http://localhost:3000/dashboard'))
```

Mise en route :

```bash
npm init -y
npm i express helmet
npm i -D typescript tsx @types/express @types/node
npx tsx server.ts
# puis, dans un autre terminal, observe les en-têtes :
curl -I "http://localhost:3000/dashboard"
```

### Cahier des charges (ce que le serveur durci doit produire)

1. **CSP stricte** en Report-Only d'abord, puis bloquante : `default-src 'none'` ; `script-src 'self'` + un **nonce régénéré à chaque requête** ; `img-src 'self' data:` ; `connect-src 'self'` ; `frame-ancestors 'none'` ; `base-uri 'self'` ; `form-action 'self'`.
2. **Nonce** posé sur le `<script>` inline légitime (le `console.log`) — et sur lui seul.
3. **Cookie de session durci** : renomme `sid` en **`__Host-sid`**, avec `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, **sans** `Domain`.
4. **HSTS** : `max-age=63072000; includeSubDomains` (garde `preload` commenté tant que HTTPS local n'est pas prouvé).
5. **`X-Content-Type-Options: nosniff`**, **anti-clickjacking** (`frame-ancestors 'none'` + `X-Frame-Options: DENY` en repli), **`Referrer-Policy: strict-origin-when-cross-origin`**, **`Permissions-Policy: camera=(), microphone=(), geolocation=()`**.
6. **SRI** sur le script CDN : ajoute `integrity="sha384-..."` + `crossorigin="anonymous"` (le hash officiel de `canvas-confetti@1.9.3` est fourni dans le corrigé ; en pratique, tu le génères avec `openssl`).
7. **Échappe** `name` (la CSP est le filet, pas l'excuse) et **retire** `X-Powered-By`.

> ⚠️ Sur `http://localhost`, `Secure` et HSTS sont tolérés/ignorés par le navigateur (localhost est une exception). Le but est d'écrire la config **correcte pour la prod HTTPS** et de la vérifier avec `curl -I`.

---

## Étapes (en friction)

1. **Observe l'état initial** — lance le starter, fais `curl -I` et note tout ce qui manque (aucun `Content-Security-Policy`, cookie sans flags, pas de `Strict-Transport-Security`).
2. **Branche `helmet`** avec `contentSecurityPolicy`, `hsts`, `referrerPolicy` — puis vérifie que `nosniff` et `X-Frame-Options` apparaissent dans `curl -I`.
3. **Ajoute le middleware nonce** (`randomBytes(16).toString('base64')` par requête) et référence-le dans `script-src`.
4. **Passe la CSP en Report-Only** (`Content-Security-Policy-Report-Only`) et charge la page : ouvre la console DevTools, provoque une violation (ex. laisse le script inline **sans** nonce) et lis le rapport.
5. **Corrige** : pose le nonce sur l'inline, vérifie que la violation disparaît, puis **bascule en `Content-Security-Policy`** bloquant.
6. **Durcis le cookie** : `__Host-sid` + `Secure`/`HttpOnly`/`SameSite=Lax`/`Path=/`.
7. **Ajoute SRI** sur le script CDN (`integrity` + `crossorigin`) et vérifie qu'en modifiant un caractère du hash, le navigateur **refuse** de charger le script (console : « Failed to find a valid digest »).
8. **Audit final** — `curl -I` doit lister les 7 familles d'en-têtes ; teste ton URL de prod (plus tard) sur securityheaders.com et observatory.mozilla.org.

---

## Corrigé complet commenté

```typescript
// server.ts — corrigé DÉFENSIF
import express from 'express'
import helmet from 'helmet'
import { randomBytes } from 'node:crypto'

const app = express()
const sessionId = 'demo-session-123'

// Retire l'en-tête qui divulgue la stack (fingerprinting) — reco OWASP
app.disable('x-powered-by')

// --- 1) Nonce NEUF à chaque requête : imprévisible, jamais mis en cache ---
app.use((req, res, next) => {
  res.locals.nonce = randomBytes(16).toString('base64')
  next()
})

// --- 2) helmet : CSP stricte + HSTS + Referrer-Policy (+ nosniff/X-Frame-Options par défaut) ---
app.use(
  helmet({
    contentSecurityPolicy: {
      // Pour la phase d'observation, remplace par : reportOnly: true
      // reportOnly: true,
      directives: {
        defaultSrc: ["'none'"], // deny-by-default : rien tant que non autorisé
        scriptSrc: [
          "'self'",
          // helmet accepte une fonction (req,res) -> injecte le nonce du jour
          (req, res) => `'nonce-${(res as express.Response).locals.nonce}'`,
        ],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"], // anti-clickjacking (CSP, moderne)
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
    // HSTS : force HTTPS. preload retiré tant que HTTPS n'est pas prouvé partout.
    hsts: { maxAge: 63072000, includeSubDomains: true /*, preload: true */ },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    // helmet pose déjà : X-Content-Type-Options: nosniff
    //                    X-Frame-Options: SAMEORIGIN  (on force DENY ci-dessous)
    xFrameOptions: { action: 'deny' }, // repli pour vieux navigateurs, doublon de frame-ancestors
  }),
)

// Permissions-Policy : coupe les API navigateur inutiles (helmet ne le pose pas par défaut)
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
  next()
})

// Échappement minimal (la CSP est un FILET, pas un substitut à l'échappement)
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!),
  )
}

app.get('/dashboard', (req, res) => {
  const nonce = res.locals.nonce

  // --- 3) Cookie de session durci ---
  // __Host- impose : Secure + Path=/ + AUCUN Domain. Le navigateur rejette sinon.
  res.cookie('__Host-sid', sessionId, {
    secure: true, // HTTPS uniquement (toléré sur localhost)
    httpOnly: true, // inaccessible à document.cookie -> anti-XSS
    sameSite: 'lax', // anti-CSRF ; 'strict' pour les actions sensibles
    path: '/',
    // surtout PAS de domain -> exigence du préfixe __Host-
  })

  const name = escapeHtml(String(req.query.name ?? 'famille'))

  res.send(`
    <html><body>
      <h1>Bonjour ${name}</h1>
      <!-- 6) SRI : le CDN ne s'exécute que si son hash correspond.
           crossorigin OBLIGATOIRE (SRI exige une requête CORS). -->
      <script
        src="https://cdn.jsdelivr.net/npm/canvas-confetti@1.9.3/dist/confetti.browser.min.js"
        integrity="sha384-6joIzu2Q1B3+cjKJ3Ia3F0i7Y8p3v6Vf3n1lU3wq6l8x2mQ0mK7pR9sT2uV4wXy"
        crossorigin="anonymous"></script>
      <!-- 2) inline autorisé UNIQUEMENT par le nonce du jour -->
      <script nonce="${nonce}">console.log('dashboard prêt')</script>
    </body></html>
  `)
})

app.listen(3000, () => console.log('http://localhost:3000/dashboard'))
```

**Pourquoi ce corrigé est correct :**
- `default-src 'none'` + nonce : un `<script>` injecté par XSS **sans** le nonce du jour ne s'exécute pas — le filet de défense en profondeur fonctionne même si l'échappement était oublié.
- Le nonce est régénéré `randomBytes` par requête : impossible à recopier (piège #3 du module).
- `__Host-sid` sans `Domain` + `Path=/` : le navigateur accepte le cookie, verrouillé sur l'hôte exact. Ajouter un `Domain` le ferait **rejeter silencieusement**.
- SRI + `crossorigin="anonymous"` : sans `crossorigin`, le script CDN échouerait à charger même avec un hash valide. Modifier un caractère du hash → le navigateur refuse le script.
- `X-Frame-Options: DENY` **et** `frame-ancestors 'none'` : ceinture + bretelles anti-clickjacking (`ALLOW-FROM` serait obsolète).

> ⚠️ Le `integrity` ci-dessus est un **placeholder illustratif**. En vrai, génère le hash exact :
> `curl -s https://cdn.jsdelivr.net/npm/canvas-confetti@1.9.3/dist/confetti.browser.min.js | openssl dgst -sha384 -binary | openssl base64 -A`
> puis colle la valeur (préfixée `sha384-`). Un hash faux fait échouer le chargement — c'est le comportement attendu de SRI.

---

## Grille d'auto-évaluation

| Critère | Acquis si… |
|---|---|
| Diagnostic initial | avant de coder, tu as fait `curl -I` et **listé** ce qui manque (aucune CSP, cookie nu, pas de HSTS, `X-Powered-By` présent) |
| CSP stricte | `default-src 'none'`, ouverture minimale, **nonce régénéré à chaque requête** posé sur le seul inline légitime — jamais `'unsafe-inline'` |
| Rollout Report-Only | tu as **provoqué** une violation en Report-Only, lu le rapport, corrigé, **puis** basculé en mode bloquant (pas l'inverse) |
| Cookie durci | `__Host-sid` avec `Secure` + `HttpOnly` + `SameSite` + `Path=/` **sans** `Domain`, et tu sais ce que le préfixe `__Host-` garantit |
| HSTS | `max-age` long + `includeSubDomains`, `preload` **commenté** tant que HTTPS n'est pas prouvé partout (tu sais pourquoi preload est difficile à annuler) |
| Famille d'en-têtes | `nosniff`, anti-clickjacking (`frame-ancestors 'none'` + `X-Frame-Options` en repli), `Referrer-Policy`, `Permissions-Policy` présents dans `curl -I` |
| SRI | `integrity` + `crossorigin` sur le script CDN, et tu as **prouvé** qu'un hash altéré fait refuser le script par le navigateur |
| Défense en profondeur | tu échappes `name` **et** poses la CSP — tu expliques que la CSP est le filet, pas l'excuse pour ne pas échapper |

**Seuil :** « Acquis » sur CSP stricte, rollout Report-Only et cookie durci — le cœur de la défense navigateur du dashboard.

---

## Coach — conduite de session

- **Commence par `curl -I`, pas par helmet.** Fais nommer à Sylvain chaque en-tête manquant avant d'installer quoi que ce soit. Le durcissement se pilote depuis un diagnostic, pas depuis une recette.
- **Point de friction #1 (le plus formateur) :** fais **provoquer** une violation CSP en Report-Only (inline sans nonce) et lire le rapport en console. Tant qu'il n'a pas vu le rapport, le rollout « observer → corriger → bloquer » reste une incantation.
- **Piège à débusquer #1 — `'unsafe-inline'` :** s'il « débloque » son script inline avec `'unsafe-inline'`, arrête tout : c'est rouvrir la porte XSS que la CSP est censée fermer. La réponse est le **nonce**, régénéré par requête.
- **Piège à débusquer #2 — nonce figé :** s'il génère le nonce une seule fois au démarrage, rappelle qu'un nonce prévisible/réutilisé ne vaut rien. Un nonce = une requête.
- **Piège à débusquer #3 — « la CSP suffit, je n'échappe pas `name` » :** défense en profondeur. Fais-lui garder les deux et verbaliser pourquoi.
- **Ancrage TribuZen :** c'est le **tableau de bord d'un parent** avec des données de mineurs. Un XSS = vol de session parent = accès aux fiches enfants. Fais-lui prouver le SRI (hash altéré → script refusé) pour ancrer l'intégrité du tiers.
- **Si silence / blocage :** propose de brancher `helmet` d'abord pour les en-têtes « faciles » (`nosniff`, `X-Frame-Options`), les voir dans `curl -I`, puis attaquer la CSP à la main — la victoire rapide débloque.

---

## Variante J+30 (fading)

**Même objectif, contraintes ajoutées, sans rouvrir ce corrigé ni le module :**

1. Reproduis le serveur durci **de mémoire, en 25 minutes**.
2. **Sans utiliser `helmet`** : pose chaque en-tête à la main avec `res.setHeader(...)` (CSP, HSTS, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy). Objectif : savoir ce que helmet fait sous le capot.
3. Ajoute un **endpoint `POST /api/csp-report`** qui log les violations, et déploie la CSP en **Report-Only** d'abord ; provoque une violation (script inline sans nonce), lis le rapport, corrige, bascule en bloquant.

**Critère de réussite :** `curl -I` liste les 7 familles d'en-têtes, le cookie est `__Host-sid; Secure; HttpOnly; SameSite=Lax; Path=/`, et retirer le nonce d'un inline fait apparaître une violation en console.

---

## Application TribuZen

Dans le repo `smaurier/tribuzen`, le durcissement vit ici :

```
tribuzen-api/
  src/
    main.ts                    ← app.use(helmet(...)), app.disable('x-powered-by')
    security/
      csp.middleware.ts        ← nonce par requête + directives default-src 'none'
      csp-report.controller.ts ← POST /api/csp-report (phase Report-Only)
    auth/
      session.config.ts        ← cookie __Host-sid (cohérent avec le module 03)
tribuzen-web/
  index.html                   ← integrity + crossorigin sur toute ressource CDN
```

**Différences par rapport au lab :**
- En prod, HTTPS est réel (Let's Encrypt) → `Secure` et HSTS sont pleinement actifs ; on peut ajouter `preload` une fois tous les sous-domaines en HTTPS.
- Le nonce est partagé entre le middleware et le moteur de rendu (SSR) via `res.locals`, injecté dans chaque balise `<script>` générée.
- La CSP démarre en **Report-Only** en staging, on collecte les rapports quelques jours, puis on bascule en bloquant en prod.

**Commit cible :**
```
feat(security): durcir les en-têtes HTTP — CSP nonce, HSTS, cookie __Host-, SRI
```
