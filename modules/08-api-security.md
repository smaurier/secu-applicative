---
titre: Sécurité des API — OWASP API Top 10, JWT bien géré, rate limiting, validation
cours: 14-securite-applicative
notions: ["OWASP API Security Top 10 2023", "JWT — valider signature / exp / aud / iss", "piège alg none", "algorithm confusion RS256 vers HS256", "secret HMAC faible", "rate limiting (429)", "validation d'entrée stricte (allowlist)", "mass assignment / over-posting", "exposition excessive de données (BOPLA)", "pagination et limites de ressources", "versioning et inventaire d'API"]
outcomes:
  - "sait situer une faille d'API dans l'OWASP API Security Top 10 2023 et la distinguer d'une faille web classique"
  - "sait valider un JWT correctement — signature, exp, aud, iss — et fermer les pièges alg=none et algorithm confusion RS256/HS256"
  - "sait poser un rate limiting qui répond 429 et durcir une API contre la consommation non maîtrisée"
  - "sait valider une entrée en allowlist et bloquer le mass assignment (over-posting) sur une ressource"
  - "sait éviter l'exposition excessive de données (sérialiser en DTO, paginer, borner) et versionner une API sans laisser d'endpoints fantômes"
prerequis:
  - "Modules 00 à 07 du cours (posture, OWASP Top 10 web, injection, authentification, autorisation, crypto, headers, CORS)"
  - "Autorisation — RBAC/ABAC, BOLA/IDOR, moindre privilège (module 04)"
  - "Authentification — sessions vs tokens, hachage, MFA (module 03)"
next: 09-supply-chain
libs: []
tribuzen: back-office TribuZen — durcissement de l'API REST (validation JWT, rate limiting, validation d'entrée, anti-mass-assignment, DTO de sortie)
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Sécurité des API — OWASP API Top 10, JWT bien géré, rate limiting, validation

> **Outcomes — tu sauras FAIRE :** situer une faille dans l'OWASP API Security Top 10 2023, valider un JWT sans laisser passer `alg=none` ni l'algorithm confusion, poser un rate limiting qui répond 429, valider une entrée en allowlist, bloquer le mass assignment, et éviter l'exposition excessive de données.
> **Difficulté :** :star::star::star:
>
> **Angle : DÉFENSIF.** On montre les failles pour les **comprendre et durcir TON API**, jamais pour attaquer un tiers. Aucun payload prêt à l'emploi contre un système externe.
>
> **Portée :** ce module traite la **sécurité propre aux API** (contrat d'entrée/sortie, tokens, débit, versions). Le **contrôle d'accès** (BOLA/IDOR, RBAC/ABAC, moindre privilège — API1/API5 du Top 10) est le **module 04**, on y renvoie sans le refaire. L'**émission** des tokens (OAuth2/OIDC + PKCE) est le **module 03b** ; le stockage des mots de passe et des sessions, le **module 03**. Ici on se concentre sur la **validation** du token et le durcissement du contrat d'API.

## 1. Cas concret d'abord

Tu reprends l'API REST de TribuZen (NestJS). Elle sert les activités des enfants d'une famille — **données de mineurs**, l'enjeu le plus sensible de l'app. Un collègue a livré ce middleware d'authentification et ce endpoint de mise à jour de profil. Ça « marche » en démo.

```typescript
// AVANT durcissement. NE PAS copier en prod.
import jwt from 'jsonwebtoken'

function auth(req, res, next) {
  const token = req.headers.authorization?.slice(7) // "Bearer xxx"
  // (1) decode NE VÉRIFIE PAS la signature — n'importe qui forge un token
  const payload = jwt.decode(token)
  req.user = payload
  next()
}

// PATCH /api/users/:id  — met à jour un profil parent
app.patch('/api/users/:id', auth, async (req, res) => {
  // (2) tout le body est écrit tel quel dans la ligne user
  const user = await db.user.update({ where: { id: req.params.id }, data: req.body })
  // (3) on renvoie la ligne entière, y compris passwordHash et role
  res.json(user)
})

// GET /api/children — liste des enfants
app.get('/api/children', auth, async (req, res) => {
  // (4) aucune pagination, aucune limite de débit
  res.json(await db.child.findMany())
})
```

**Quatre trous que ce module va boucher :**

1. **JWT non vérifié** — `jwt.decode` lit le payload **sans contrôler la signature**. Un attaquant fabrique `{ "sub": "...", "role": "admin" }`, le passe en base64, et devient admin. Il faut `jwt.verify` avec une clé, un algorithme **imposé**, et une vérification de `exp`/`aud`/`iss`.
2. **Mass assignment** — `data: req.body` écrit **n'importe quel champ** envoyé. Un client malicieux ajoute `"role": "admin"` ou `"familyId": "<autre famille>"` au body et s'élève. Il faut une **allowlist** de champs modifiables.
3. **Exposition excessive de données** — renvoyer la ligne brute expose `passwordHash`, `role`, notes internes. Il faut sérialiser vers un **DTO de sortie**.
4. **Consommation non maîtrisée** — pas de pagination ni de rate limiting : un `GET /api/children` peut vider la base, et le login est ouvert au brute-force. Il faut **borner** et **limiter** (réponse `429`).

À la fin du module, cette API vérifie ses tokens correctement, n'écrit que les champs autorisés, ne renvoie que des DTO, pagine et limite le débit. C'est le fil rouge du lab.

---

## 2. Théorie complète, concise

### 2.1 Pourquoi les API ont leur propre Top 10

Une API n'a pas d'UI qui masque des champs ou impose un parcours : le client parle **directement** au contrat. Les défenses « côté écran » n'existent pas. L'OWASP a donc un référentiel dédié, le **API Security Top 10 (édition 2023, vérifiée 2026-07)** :

| ID | Catégorie | En un mot | Où on la traite |
|---|---|---|---|
| **API1:2023** | Broken Object Level Authorization (BOLA) | accéder à l'objet d'un autre via son id | **module 04** |
| **API2:2023** | Broken Authentication | auth/token mal implémentés | §2.2–2.4 (ici) + module 03 |
| **API3:2023** | Broken Object Property Level Authorization (BOPLA) | lire/écrire des **propriétés** non autorisées (mass assignment + exposition) | §2.6–2.7 (ici) |
| **API4:2023** | Unrestricted Resource Consumption | pas de limite CPU/mémoire/débit | §2.5 (ici) |
| **API5:2023** | Broken Function Level Authorization | accéder à une **fonction** admin sans droit | **module 04** |
| **API6:2023** | Unrestricted Access to Sensitive Business Flows | abus automatisé d'un flux métier | §2.5 (ici) |
| **API7:2023** | Server Side Request Forgery (SSRF) | l'API fetch une URI fournie sans validation | §2.8 (survol) |
| **API8:2023** | Security Misconfiguration | config par défaut, headers manquants | modules 06/10 |
| **API9:2023** | Improper Inventory Management | endpoints/versions fantômes non documentés | §2.9 (ici) |
| **API10:2023** | Unsafe Consumption of APIs | faire trop confiance à une API tierce | module 09 + §2.8 |

> **Le fait marquant 2023 :** les trois premières places sont des failles d'**autorisation**, pas d'injection. Sur une API, la question n'est presque jamais « est-ce filtré ? » mais « **cet appelant a-t-il le droit sur CET objet et CETTE propriété ?** ». BOLA/BOFLA (API1/API5) sont détaillés au **module 04** ; ici on prend BOPLA (API3), la consommation (API4/API6) et l'inventaire (API9).

### 2.2 Un JWT, décomposé

Un JWT est trois parties base64url séparées par des points : `header.payload.signature`.

- **header** — `{ "alg": "RS256", "typ": "JWT" }` : l'algorithme **déclaré**.
- **payload** — les *claims* : `sub` (sujet), `exp` (expiration), `iat`, `aud` (audience), `iss` (émetteur), plus tes claims (`role`, `familyId`…).
- **signature** — `alg(base64(header) + "." + base64(payload), clé)`.

Point capital : **le payload n'est pas chiffré, juste encodé**. N'importe qui le lit. La seule chose qui empêche un attaquant de le **modifier**, c'est la vérification de la **signature** côté serveur. `jwt.decode()` lit sans vérifier — c'est le trou n°1 du §1. La bonne primitive est `jwt.verify()`.

### 2.3 Valider un JWT correctement

Vérifier la signature ne suffit pas : il faut aussi valider les **claims temporels et de destination**. OWASP (REST Security Cheat Sheet) : valider systématiquement `iss`, `aud`, `exp` et `nbf`.

```typescript
import jwt from 'jsonwebtoken'

// Clé publique de l'émetteur (OIDC → module 03b). En RS256, on ne détient QUE la publique.
const PUBLIC_KEY = process.env.JWT_PUBLIC_KEY!

function verifyAccessToken(token: string) {
  return jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],           // IMPOSE l'algo — cœur de la défense (§2.4)
    audience: 'tribuzen-api',        // aud : ce token m'est-il destiné ?
    issuer: 'https://auth.tribuzen.app', // iss : émis par MON serveur d'auth ?
    // exp est vérifié par défaut ; clockTolerance pour la dérive d'horloge :
    clockTolerance: 5,               // 5 s de tolérance
  })
  // Lève une erreur si : signature invalide, exp dépassé, aud/iss non conformes, alg non listé.
}
```

Checklist de validation d'un token d'accès :

1. **Signature** vérifiée avec la bonne clé (`verify`, pas `decode`).
2. **`algorithms`** passé en dur — jamais déduit du header (§2.4).
3. **`exp`** (expiration) présent et non dépassé. Un token sans `exp` est un token éternel.
4. **`aud`** (audience) == ton API : un token émis pour un autre service ne doit pas ouvrir la tienne.
5. **`iss`** (issuer) == ton serveur d'auth attendu.
6. **`nbf`** (not before) si présent.

### 2.4 Les deux pièges JWT qui coûtent le plus cher

**Piège A — `alg: none`.** La spec JWT prévoit un algorithme « none » (JWT non signé). Si ta lib l'accepte, un attaquant met `{ "alg": "none" }` dans le header, met une **signature vide**, et forge le payload qu'il veut. OWASP est explicite : **« ne pas autoriser les JWT non sécurisés `{"alg":"none"}` »**. Parade : toujours passer une **allowlist d'algorithmes** à `verify` (`algorithms: ['RS256']`) — `none` n'en fait jamais partie.

**Piège B — algorithm confusion RS256 → HS256.** RS256 est **asymétrique** : signé avec la clé **privée**, vérifié avec la clé **publique** (que tout le monde peut connaître). HS256 est **symétrique** : la **même clé** signe et vérifie. Si ton code sélectionne l'algo d'après le header du token, un attaquant :

1. prend ta clé **publique RS256** (elle est publique) ;
2. forge un token en **HS256** signé avec cette clé publique **comme si c'était un secret HMAC** ;
3. ton serveur lit `alg: HS256`, prend la clé RSA « publique » comme secret HMAC, et… la signature est valide.

Règle OWASP (JWT / algorithm confusion) : **le serveur ne doit jamais choisir l'algorithme de vérification d'après le header du JWT ; il l'impose depuis sa propre configuration.** C'est exactement ce que fait `algorithms: ['RS256']` ci-dessus.

**Piège C — secret HMAC faible (si tu utilises HS256).** En HS256, la sécurité tient entièrement au secret. Un secret court ou devinable (`"secret"`, `"tribuzen"`) se brute-force hors ligne à partir d'un seul token capturé. Si HS256, le secret doit être **aléatoire, ≥ 256 bits**, généré par un CSPRNG, stocké hors code (env/KMS). Pour une API exposée à plusieurs services, **préférer RS256** : les consommateurs n'ont que la clé publique et ne peuvent pas forger de token (OWASP : préférer les signatures aux MAC).

### 2.5 Rate limiting et consommation de ressources (API4/API6)

Sans limite de débit, une API subit brute-force, scraping et déni de service. La réponse standard quand le seuil est franchi est **HTTP 429 Too Many Requests** (OWASP REST Cheat Sheet).

```typescript
import rateLimit from 'express-rate-limit'

// Limiteur global : 100 requêtes / 15 min / IP
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-7',   // en-têtes RateLimit standard
  legacyHeaders: false,
  message: { error: 'Trop de requêtes' }, // renvoyé avec un statut 429
})

// Limiteur serré sur l'authentification : 5 essais / 15 min (anti brute-force)
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5 })

app.use('/api/', apiLimiter)
app.use('/api/auth/login', authLimiter)
```

Au-delà du débit, **borner les autres ressources** (API4) : taille du body (`express.json({ limit: '100kb' })`), profondeur/longueur des payloads, timeout des requêtes, et **pagination obligatoire** (§2.7). **API6** (flux métier sensibles) va plus loin : un flux comme « inviter un membre » ou « exporter les données famille » doit résister à l'**automatisation** (throttling par compte, CAPTCHA, détection d'anomalie) même si chaque requête isolée est légitime.

> Le rate limiting **par IP** est un premier rempart, mais les IP tournent (mobile, proxies). Compléter par une limite **par compte/token** pour les flux sensibles.

### 2.6 Validation d'entrée stricte et mass assignment (API3)

**Ne jamais faire confiance au body.** Valider en **allowlist** : on décrit ce qui est **autorisé**, tout le reste est rejeté ou ignoré — pas l'inverse.

```typescript
import { z } from 'zod'

// Allowlist : SEULS ces champs existent pour l'API. Un champ en trop est rejeté.
const UpdateProfileSchema = z.object({
  displayName: z.string().min(2).max(80).trim(),
  locale: z.enum(['fr', 'en']),
}).strict() // .strict() → un champ inconnu ("role", "familyId") fait ÉCHOUER la validation

app.patch('/api/users/:id', auth, async (req, res) => {
  const parsed = UpdateProfileSchema.safeParse(req.body)
  if (!parsed.success) {
    return res.status(400).json({ error: 'Requête invalide', details: parsed.error.flatten() })
  }
  // parsed.data ne contient QUE displayName + locale — impossible d'écrire role/passwordHash
  const user = await db.user.update({ where: { id: req.params.id }, data: parsed.data })
  res.json(toUserDto(user)) // DTO de sortie, cf. §2.7
})
```

Le **mass assignment** (ou *over-posting*, API3:2023 BOPLA) est le trou n°2 du §1 : lier tout le body à l'entité laisse un attaquant écrire des propriétés qu'il ne devrait pas toucher (`role`, `isVerified`, `familyId`). Deux parades cumulables :

- **Allowlist de champs** — un schéma `.strict()` (Zod) ou un DTO NestJS avec `whitelist: true` + `forbidNonWhitelisted: true` dans le `ValidationPipe`. Le serveur ne voit jamais les champs en trop.
- **Ne jamais passer `req.body` directement** à `db.update` / `Object.assign(entity, body)` : reconstruire un objet **explicite** champ par champ.

> **Validation ≠ échappement.** Valider borne la **forme** (type, longueur, énumération). L'échappement/paramétrage contre l'injection (SQLi, XSS) est le **module 02** — les deux sont nécessaires, pas interchangeables.

### 2.7 Exposition excessive de données et pagination (API3/API4)

**Exposition excessive** (trou n°3 du §1) : renvoyer l'entité brute expose des champs internes. La parade est de **sérialiser vers un DTO de sortie** — une allowlist de sortie — plutôt que de compter sur le client pour « ne pas afficher » les champs sensibles.

```typescript
interface UserRow { id: string; email: string; displayName: string; role: string; passwordHash: string }

// DTO de sortie : SEULS les champs publics. Ajouter un champ à UserRow n'expose RIEN par défaut.
function toUserDto(u: UserRow) {
  return { id: u.id, email: u.email, displayName: u.displayName }
}
```

Ne jamais faire de « filtrage côté client » : l'API a déjà envoyé `passwordHash` sur le réseau, le mal est fait. Le filtrage doit être **côté serveur**, par construction (NestJS : `class-transformer` + `@Exclude()`/`@Expose()` avec `excludeExtraneousValues: true`).

**Pagination obligatoire** (trou n°4) : tout endpoint de liste borne son volume, sinon une seule requête peut vider la base (API4).

```typescript
const PageSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20), // plafond DUR à 100
})

app.get('/api/children', auth, async (req, res) => {
  const { page, limit } = PageSchema.parse(req.query)
  const rows = await db.child.findMany({ skip: (page - 1) * limit, take: limit })
  res.json({ page, limit, items: rows.map(toChildDto) })
})
```

Le **plafond dur** (`max(100)`) est essentiel : sans lui, un client demande `limit=10000000` et provoque le déni de service que la pagination était censée éviter.

### 2.8 SSRF et consommation d'API tierces (survol — API7/API10)

Quand ton API **fetch une URL fournie par l'utilisateur** (import depuis un lien, webhook, avatar distant), un attaquant peut viser des ressources **internes** (`http://169.254.169.254/` métadonnées cloud, `http://localhost:...`) : c'est la **SSRF** (API7). Défense : **allowlist de domaines/schémas**, refuser les IP privées/loopback, ne pas suivre les redirections vers des cibles internes. Le détail infra (métadonnées cloud, egress) est déféré au **cours 12**. Symétriquement, **API10** rappelle de ne pas faire aveuglément confiance aux données reçues d'une API tierce (les valider comme une entrée utilisateur) — approfondi au **module 09 (supply chain)**.

### 2.9 Versioning sûr et inventaire (API9)

**API9:2023 (Improper Inventory Management)** : les API exposent plus d'endpoints qu'une app web, et les **vieilles versions oubliées** deviennent le maillon faible (un `/api/v1` non patché encore joignable).

- **Versionner explicitement** (`/api/v1`, `/api/v2`) et **documenter** chaque version (OpenAPI à jour = source de vérité).
- **Déprécier proprement** : en-têtes `Deprecation` et `Sunset`, communication, puis **extinction effective** — un endpoint déprécié mais toujours en ligne reste une surface d'attaque.
- **Pas d'endpoint « fantôme »** : les environnements de debug/staging exposés en prod (API8/API9) sont une cause fréquente de fuite.

```typescript
app.use('/api/v1', (req, res, next) => {
  res.setHeader('Deprecation', 'true')
  res.setHeader('Sunset', 'Wed, 01 Jul 2026 00:00:00 GMT') // date d'extinction RÉELLE, puis on coupe
  res.setHeader('Link', '</api/v2>; rel="successor-version"')
  next()
})
```

---

## 3. Worked examples

### Exemple 1 — Middleware d'auth JWT durci (TribuZen)

On reprend le middleware du §1 et on ferme les pièges `decode`, `alg=none` et algorithm confusion.

```typescript
// auth.middleware.ts — APRÈS durcissement
import jwt from 'jsonwebtoken'
import type { Request, Response, NextFunction } from 'express'

const PUBLIC_KEY = process.env.JWT_PUBLIC_KEY! // clé PUBLIQUE RS256 (module 03b émet les tokens)

interface TokenClaims { sub: string; role: 'parent' | 'admin'; familyId: string }

export function auth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requis' }) // 401 : authN échoue (module 03)
  }
  const token = header.slice(7)

  try {
    // verify (PAS decode) : contrôle la signature ET les claims.
    const claims = jwt.verify(token, PUBLIC_KEY, {
      algorithms: ['RS256'],              // ferme alg=none ET algorithm confusion (RS→HS)
      audience: 'tribuzen-api',           // aud : ce token vise bien cette API
      issuer: 'https://auth.tribuzen.app', // iss : émis par notre serveur d'auth
      clockTolerance: 5,
    }) as TokenClaims

    // On ne recopie QUE les claims attendus (pas tout le payload) → surface minimale.
    req.user = { id: claims.sub, role: claims.role, familyId: claims.familyId }
    next()
  } catch {
    // Message générique : ne pas révéler pourquoi (exp ? signature ? aud ?).
    return res.status(401).json({ error: 'Token invalide' })
  }
}
```

**Ce qui a changé :** `verify` au lieu de `decode` (signature contrôlée) ; `algorithms: ['RS256']` en dur (ferme `alg=none` **et** l'algorithm confusion) ; `aud`/`iss`/`exp` validés ; seuls les claims attendus recopiés dans `req.user`. Noter que **savoir si ce parent a le droit de voir CETTE famille** reste de l'**autorisation → module 04** : l'auth vérifie *qui*, pas *quoi*.

### Exemple 2 — Endpoint `PATCH` anti-mass-assignment + DTO de sortie

On reprend le endpoint de profil du §1 et on ferme les trous 2 et 3.

```typescript
// users.controller.ts — APRÈS durcissement
import { z } from 'zod'

// Allowlist d'ENTRÉE : seuls ces deux champs sont modifiables par le client.
const UpdateProfileSchema = z.object({
  displayName: z.string().min(2).max(80).trim(),
  locale: z.enum(['fr', 'en']),
}).strict() // un champ en trop ("role", "familyId") → 400, pas une élévation de privilège

// Allowlist de SORTIE : jamais passwordHash / role bruts sur le réseau.
function toUserDto(u: { id: string; email: string; displayName: string; locale: string }) {
  return { id: u.id, email: u.email, displayName: u.displayName, locale: u.locale }
}

app.patch('/api/users/:id', auth, async (req, res) => {
  const parsed = UpdateProfileSchema.safeParse(req.body)
  if (!parsed.success) {
    return res.status(400).json({ error: 'Requête invalide', details: parsed.error.flatten() })
  }

  // data = objet EXPLICITE issu du schéma, jamais req.body brut.
  const updated = await db.user.update({
    where: { id: req.params.id },
    data: { displayName: parsed.data.displayName, locale: parsed.data.locale },
  })

  res.json(toUserDto(updated)) // DTO de sortie → pas de fuite de champ interne
})
```

**Ce qui a changé :** schéma `.strict()` en allowlist d'entrée (mass assignment fermé), objet `data` explicite (pas de `req.body` propagé), et DTO de sortie (exposition excessive fermée). Un attaquant qui ajoute `"role": "admin"` au body reçoit un `400`, pas les droits admin.

---

## 4. Pièges & misconceptions

### PIÈGE #1 — `jwt.decode()` au lieu de `jwt.verify()`
`decode` **lit** le payload sans vérifier la signature — un token entièrement forgé passe. Toujours `verify` avec une clé **et** une allowlist d'algorithmes. `decode` ne sert qu'à inspecter un token **déjà vérifié** (ou en debug), jamais pour authentifier.

### PIÈGE #2 — Laisser la lib choisir l'algorithme d'après le header du token
C'est la porte de `alg=none` **et** de l'algorithm confusion RS256→HS256. OWASP : le serveur **impose** l'algorithme depuis sa config, il ne le lit jamais dans le header du JWT. Correct : `algorithms: ['RS256']` passé à `verify`.

### PIÈGE #3 — « Le JWT est chiffré, donc je peux y mettre des secrets »
Faux. Le payload est **base64url, pas chiffré** : tout le monde le lit. Ne jamais y mettre de donnée sensible (mot de passe, PII inutile). La signature garantit l'**intégrité**, pas la **confidentialité**. (Pour chiffrer un token → JWE, hors module.)

### PIÈGE #4 — Confondre validation d'entrée et contrôle d'accès
Valider que `role` a une forme correcte n'autorise pas à le **modifier**. Le mass assignment (API3) et le BOLA (API1, module 04) sont distincts : le premier est « quelles **propriétés** puis-je écrire ? », le second « quel **objet** puis-je toucher ? ». Il faut les deux.

### PIÈGE #5 — Denylist de champs au lieu d'allowlist
Bloquer explicitement `passwordHash` et `role` (denylist) casse au **prochain champ sensible ajouté** au modèle : il sera exposé par défaut. L'allowlist (DTO de sortie, schéma `.strict()`) est sûre par construction — un nouveau champ n'est exposé que si on l'ajoute sciemment.

### PIÈGE #6 — Pagination sans plafond dur
`limit` piloté par le client sans `max()` : `?limit=10000000` provoque le déni de service (API4) que la pagination devait empêcher. Toujours un **plafond serveur** (ex. 100), indépendant de la valeur demandée.

### PIÈGE #7 — Rate limiting uniquement par IP
Les IP tournent (NAT mobile, proxies, botnets). Une limite par IP seule est contournable et peut bloquer des utilisateurs légitimes derrière un même NAT. Compléter par une limite **par compte/token** sur les flux sensibles (login, invitations, export).

### PIÈGE #8 — Vieilles versions d'API laissées en ligne
Un `/api/v1` déprécié mais toujours joignable et non patché (API9) est une surface d'attaque oubliée. Déprécier = annoncer (`Sunset`) **puis couper effectivement**, pas juste ajouter un header.

---

## 5. Ancrage TribuZen

L'API TribuZen sert des **données de mineurs** : le durcissement du contrat d'API n'est pas optionnel. Où ça vit dans `smaurier/tribuzen` (back-office NestJS) :

```
tribuzen-api/
  src/
    auth/
      jwt.strategy.ts        ← verify RS256 imposé, aud/iss/exp validés (Exemple 1)
    common/
      guards/throttler.guard.ts   ← rate limiting 429 (login serré, global large)
      pipes/validation.pipe.ts    ← whitelist:true + forbidNonWhitelisted:true (anti mass assignment)
      interceptors/serialize.ts   ← DTO de sortie (@Exclude passwordHash/role) — exposition excessive
    users/
      dto/update-profile.dto.ts   ← allowlist d'entrée stricte (Exemple 2)
    children/
      children.controller.ts      ← pagination bornée (plafond dur 100)
```

Points d'ancrage concrets :

- **Validation JWT** : `JwtStrategy` impose `algorithms: ['RS256']`, `audience: 'tribuzen-api'`, `issuer` du serveur d'auth (module 03b). Jamais `decode`.
- **Rate limiting** : `@nestjs/throttler` — 5/15 min sur `/auth/login` et `/auth/login/totp`, large ailleurs, réponse `429`.
- **Mass assignment** : `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })` global + DTO par endpoint. `role`/`familyId` jamais modifiables par le body.
- **Exposition** : `ClassSerializerInterceptor` + `@Exclude()` sur `passwordHash`, `mfaSecret`, notes internes.
- **Autorisation** (ce parent voit-il CETTE famille / cet enfant ?) → **module 04**, pas ici.

---

## 6. Points clés

1. Les API ont leur propre référentiel : **OWASP API Security Top 10 2023**, dominé par les failles d'**autorisation** (API1/API3/API5).
2. Valider un JWT = `verify` (pas `decode`) + **signature** + `exp` + `aud` + `iss`, avec une **allowlist d'algorithmes en dur**.
3. `algorithms: ['<algo>']` imposé côté serveur ferme d'un coup **`alg=none`** et l'**algorithm confusion RS256→HS256** — ne jamais lire l'algo dans le header du token.
4. En HS256, le secret doit être **aléatoire ≥ 256 bits** hors code ; pour une API multi-services, **préférer RS256** (clé publique diffusable, non forgeable).
5. **Rate limiting** → réponse **429** ; borner aussi taille de body, timeouts et **paginer avec un plafond dur** (API4/API6).
6. **Mass assignment** (API3) : valider en **allowlist stricte** (`.strict()`, `whitelist`), ne jamais lier `req.body` brut à l'entité.
7. **Exposition excessive** : sérialiser vers un **DTO de sortie** côté serveur ; filtrer côté client est trop tard.
8. **Versioning/inventaire** (API9) : documenter, déprécier avec `Sunset`, puis **éteindre effectivement** — pas d'endpoint fantôme.
9. Le **contrôle d'accès par objet** (BOLA/BOFLA, API1/API5) est traité au **module 04** : l'auth dit *qui*, l'autorisation dit *quoi*.

---

## 7. Seeds Anki

```
Quelle est la différence entre jwt.decode et jwt.verify ?|decode LIT le payload sans contrôler la signature (un token forgé passe) ; verify contrôle la signature avec une clé ET une allowlist d'algorithmes, plus exp/aud/iss. On authentifie TOUJOURS avec verify.
Comment ferme-t-on le piège alg=none et l'algorithm confusion d'un coup ?|En passant une allowlist d'algorithmes en dur à verify (algorithms: ['RS256']). Le serveur impose l'algo depuis sa config et ne le lit JAMAIS dans le header du token.
En quoi consiste l'algorithm confusion RS256 vers HS256 ?|L'attaquant prend la clé PUBLIQUE RS256 (publique par nature) et forge un token HS256 en l'utilisant comme secret HMAC. Si le serveur choisit l'algo d'après le header, il valide. Parade : imposer algorithms:['RS256'].
Quels claims valider sur un JWT au-delà de la signature ?|exp (expiration, sinon token éternel), aud (ce token vise bien mon API), iss (émis par mon serveur d'auth attendu), et nbf si présent.
Qu'est-ce que le mass assignment (over-posting) et comment le bloquer ?|Lier tout req.body à l'entité laisse écrire des champs interdits (role, familyId). Parade : allowlist stricte (Zod .strict() / NestJS whitelist+forbidNonWhitelisted) et objet data explicite, jamais req.body brut.
Pourquoi renvoyer un DTO de sortie plutôt que l'entité brute ?|L'entité brute expose passwordHash/role/notes internes (exposition excessive, API3). Un DTO est une allowlist de sortie côté serveur : filtrer côté client est trop tard, la donnée a déjà transité.
Quel statut HTTP renvoie une API qui a dépassé sa limite de débit ?|429 Too Many Requests. Compléter le rate limiting par IP avec une limite par compte/token sur les flux sensibles, et paginer avec un plafond dur (ex. max 100).
Pourquoi ne jamais mettre de secret dans le payload d'un JWT ?|Le payload est base64url, PAS chiffré : tout le monde le lit. La signature garantit l'intégrité, pas la confidentialité. Pour de la PII sensible, ne pas la mettre dans le token.
Où s'arrête ce module et où commence le module 04 sur une API ?|Ici : contrat d'API (validation JWT, débit, entrée/sortie, versions). Module 04 : contrôle d'accès par objet et par fonction (BOLA/BOFLA, API1/API5) — l'auth dit QUI, l'autorisation dit QUOI.
```

---

## Pont vers le lab

> Lab associé : `labs/lab-08-api-security/README.md`. Exercice **défensif** : durcir une API TribuZen fragile — remplacer `jwt.decode` par une validation `verify` complète (algo imposé, aud/iss/exp), poser un rate limiting (429), valider les entrées en allowlist stricte (anti mass assignment) et sérialiser les sorties en DTO. Vrai outil (Express/Zod/jsonwebtoken), pas de harnais simulé. Corrigé commenté + variante J+30.
