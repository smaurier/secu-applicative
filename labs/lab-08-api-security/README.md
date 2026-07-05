# Lab 08 — Durcir une API TribuZen

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

> **Outcome :** à la fin, tu sais durcir une API REST vulnérable — valider un JWT correctement (`verify` + algo imposé + `aud`/`iss`/`exp`), poser un rate limiting qui répond `429`, valider les entrées en allowlist stricte (anti mass assignment) et sérialiser les sorties en DTO.
> **Vrai outil :** Node + Express + `jsonwebtoken` + `zod` + `express-rate-limit` (aucun harnais simulé — tu lances un vrai serveur et tu l'interroges au curl/REST client).
> **Angle : DÉFENSIF.** Tu **durcis TON API**. Aucune attaque contre un système tiers.
> **Feedback :** le coach valide en session (pas de test-runner auto-correcteur).

---

## Énoncé

On te donne une API TribuZen (parents + enfants) qui « marche » mais qui est **trouée sur quatre points** vus au module 08. Ta mission : la durcir, endpoint par endpoint, en **vérifiant chaque correction avec un vrai appel HTTP**.

Les données sont des profils de parents et des **fiches d'enfants** — donc des données de mineurs : chaque trou est un vrai risque, pas un exercice abstrait.

### Starter minimal

Crée un projet et installe les vrais outils :

```bash
mkdir tribuzen-api-hardening && cd $_
npm init -y
npm i express jsonwebtoken zod express-rate-limit
npm i -D tsx typescript @types/express @types/jsonwebtoken
```

`server.ts` — **version vulnérable de départ** (à durcir, ne pas livrer telle quelle) :

```typescript
// server.ts — VULNÉRABLE. C'est le point de départ à corriger.
import express from 'express'
import jwt from 'jsonwebtoken'

const app = express()
app.use(express.json()) // pas de limite de taille

// Secret HMAC faible + partagé — à revoir (idéalement RS256, cf. étapes)
const SECRET = 'tribuzen'

// "Base de données" en mémoire
const users = [
  { id: 'u1', email: 'lea@tribuzen.app', displayName: 'Léa', locale: 'fr', role: 'parent', passwordHash: '$argon2id$...' },
]
const children = Array.from({ length: 500 }, (_, i) => ({
  id: `c${i}`, firstName: `Enfant ${i}`, familyId: 'f1', medicalNotes: 'confidentiel',
}))

// --- Trou n°1 : JWT non vérifié ---
function auth(req: any, res: any, next: any) {
  const token = req.headers.authorization?.slice(7)
  req.user = jwt.decode(token) // ne vérifie NI signature NI exp NI aud
  if (!req.user) return res.status(401).json({ error: 'Token requis' })
  next()
}

// --- Trou n°2 (mass assignment) + n°3 (exposition) ---
app.patch('/api/users/:id', auth, (req, res) => {
  const user = users.find(u => u.id === req.params.id)
  if (!user) return res.status(404).json({ error: 'Introuvable' })
  Object.assign(user, req.body)   // écrit N'IMPORTE quel champ (role, passwordHash…)
  res.json(user)                  // renvoie la ligne ENTIÈRE
})

// --- Trou n°4 : ni pagination ni rate limiting ---
app.get('/api/children', auth, (_req, res) => {
  res.json(children) // 500 lignes + medicalNotes, à chaque appel
})

// Endpoint utilitaire pour l'exercice : émet un token de test (simule le module 03b)
app.post('/api/_dev/token', (req, res) => {
  res.json({ token: jwt.sign({ sub: 'u1', role: 'parent', familyId: 'f1' }, SECRET, { algorithm: 'HS256' }) })
})

app.listen(3000, () => console.log('http://localhost:3000'))
```

Lance-le : `npx tsx server.ts`. Récupère un token via `POST /api/_dev/token` et confirme d'abord que les trous existent (voir Étapes).

---

## Étapes (en friction)

Tu écris le code toi-même — **pas de gap-fill**. Pour chaque trou : (a) prouve la faille par un appel HTTP, (b) corrige, (c) re-prouve que c'est fermé.

1. **Constate le JWT non vérifié.** Forge un token à la main (header + payload base64url, signature bidon) avec `role: "admin"`, envoie-le sur `GET /api/children`. Il passe. → À fermer à l'étape 2.
2. **Durcis l'auth.** Remplace `jwt.decode` par `jwt.verify` avec : `algorithms` **en dur**, `audience`, `issuer` et une gestion d'`exp`. Fais émettre le token de dev avec les mêmes `aud`/`iss`. Ne recopie dans `req.user` que les claims attendus (`sub`, `role`, `familyId`). Re-teste : le token forgé et le token `alg:none` doivent tomber en `401`.
3. **(Bonus RS256)** Génère une paire de clés (`openssl genpkey` / `openssl rsa -pubout`), signe le token de dev en **RS256** avec la privée, vérifie avec la publique, et impose `algorithms: ['RS256']`. Explique au coach pourquoi ça ferme aussi l'algorithm confusion.
4. **Constate le mass assignment.** `PATCH /api/users/u1` avec `{ "displayName": "X", "role": "admin" }` → observe que `role` a changé. → À fermer.
5. **Valide l'entrée en allowlist.** Écris un schéma Zod `.strict()` (`displayName`, `locale` seulement), rejette en `400` tout champ inconnu, et construis un objet `data` **explicite** (pas `Object.assign(user, req.body)`). Re-teste : le body avec `role` doit renvoyer `400`.
6. **Ferme l'exposition.** Écris `toUserDto` (allowlist de sortie : ni `passwordHash` ni `role`) et renvoie-le. Vérifie qu'aucune réponse ne contient `passwordHash`.
7. **Pagine + borne.** Ajoute un schéma `page`/`limit` avec **plafond dur** (`max(100)`), applique `skip`/`take`, sérialise les enfants en DTO (sans `medicalNotes`). Teste `?limit=100000` → doit être ramené à 100.
8. **Rate limiting.** Ajoute `express-rate-limit` (large global, serré sur un endpoint sensible) et `express.json({ limit: '100kb' })`. Envoie une rafale d'appels → tu dois recevoir des `429`.
9. **Cas limites :** token sans `exp` (doit être refusé si tu l'imposes), `aud` erroné → `401`, body vide → `400`, `page=0` → rejeté.

---

## Corrigé complet commenté

```typescript
// server.ts — DURCI
import express from 'express'
import jwt from 'jsonwebtoken'
import { z } from 'zod'
import rateLimit from 'express-rate-limit'

const app = express()
app.use(express.json({ limit: '100kb' })) // (8) borne la taille du body (API4)

// --- Clés : RS256 (recommandé pour une API). En dev, charger depuis des fichiers/env. ---
const PRIVATE_KEY = process.env.JWT_PRIVATE_KEY! // signe (côté serveur d'auth, module 03b)
const PUBLIC_KEY = process.env.JWT_PUBLIC_KEY!   // vérifie (côté API)
const ISSUER = 'https://auth.tribuzen.app'
const AUDIENCE = 'tribuzen-api'

const users = [
  { id: 'u1', email: 'lea@tribuzen.app', displayName: 'Léa', locale: 'fr', role: 'parent', passwordHash: '$argon2id$...' },
]
const children = Array.from({ length: 500 }, (_, i) => ({
  id: `c${i}`, firstName: `Enfant ${i}`, familyId: 'f1', medicalNotes: 'confidentiel',
}))

// (2) Rate limiting : large en global, serré sur les endpoints sensibles.
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: 'draft-7', legacyHeaders: false })
app.use('/api/', apiLimiter) // dépassement → 429 automatique

interface Claims { sub: string; role: 'parent' | 'admin'; familyId: string }

// (2)(3) Auth durcie : verify + algo IMPOSÉ + aud/iss/exp.
function auth(req: any, res: any, next: any) {
  const header = req.headers.authorization
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Token requis' })
  try {
    const claims = jwt.verify(header.slice(7), PUBLIC_KEY, {
      algorithms: ['RS256'],  // ferme alg=none ET l'algorithm confusion RS256→HS256
      audience: AUDIENCE,     // ce token vise bien cette API
      issuer: ISSUER,         // émis par notre serveur d'auth
      clockTolerance: 5,      // exp vérifié par défaut ; petite tolérance d'horloge
    }) as Claims
    // Surface minimale : on ne recopie QUE les claims attendus.
    req.user = { id: claims.sub, role: claims.role, familyId: claims.familyId }
    next()
  } catch {
    return res.status(401).json({ error: 'Token invalide' }) // message générique
  }
}

// (5) Allowlist d'ENTRÉE stricte : un champ en trop → 400 (anti mass assignment).
const UpdateProfile = z.object({
  displayName: z.string().min(2).max(80).trim(),
  locale: z.enum(['fr', 'en']),
}).strict()

// (6) Allowlist de SORTIE : jamais passwordHash / role bruts.
const toUserDto = (u: typeof users[number]) => ({ id: u.id, email: u.email, displayName: u.displayName, locale: u.locale })
const toChildDto = (c: typeof children[number]) => ({ id: c.id, firstName: c.firstName }) // pas de medicalNotes

app.patch('/api/users/:id', auth, (req, res) => {
  const parsed = UpdateProfile.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: 'Requête invalide', details: parsed.error.flatten() })

  const user = users.find(u => u.id === req.params.id)
  if (!user) return res.status(404).json({ error: 'Introuvable' })
  // NB : "ce parent a-t-il le droit de modifier CET utilisateur ?" = autorisation → module 04.

  // data EXPLICITE — jamais Object.assign(user, req.body).
  user.displayName = parsed.data.displayName
  user.locale = parsed.data.locale
  res.json(toUserDto(user)) // DTO de sortie
})

// (7) Pagination bornée : plafond DUR à 100.
const Page = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
})

app.get('/api/children', auth, (req, res) => {
  const q = Page.safeParse(req.query)
  if (!q.success) return res.status(400).json({ error: 'Pagination invalide' })
  const { page, limit } = q.data
  const items = children.slice((page - 1) * limit, (page - 1) * limit + limit).map(toChildDto)
  res.json({ page, limit, items })
})

// Émetteur de token de dev : signe en RS256 avec aud/iss/exp (simule le module 03b).
app.post('/api/_dev/token', (_req, res) => {
  const token = jwt.sign({ role: 'parent', familyId: 'f1' }, PRIVATE_KEY, {
    algorithm: 'RS256', subject: 'u1', audience: AUDIENCE, issuer: ISSUER, expiresIn: '15m',
  })
  res.json({ token })
})

app.listen(3000, () => console.log('http://localhost:3000'))
```

**Pourquoi ce corrigé est correct :**
- `verify` + `algorithms: ['RS256']` : un token forgé, un `alg:none` ou un token HS256 confusionné échouent tous — le serveur n'a jamais lu l'algo dans le header.
- `audience`/`issuer`/`exp` : un token émis pour un autre service, par un autre émetteur, ou périmé, est refusé.
- `.strict()` + affectation explicite : impossible d'écrire `role`/`passwordHash` via le body (mass assignment fermé), et le client reçoit `400` plutôt qu'une élévation silencieuse.
- DTO de sortie : `passwordHash`, `role`, `medicalNotes` ne transitent jamais.
- Plafond `max(100)` + `express.json({ limit })` + rate limiter : la consommation est bornée (API4), `429` au-delà.
- Ce qui **reste** hors périmètre : « ce parent voit-il CETTE famille ? » = autorisation par objet (BOLA, API1) → **module 04**.

**Génération des clés de dev :**
```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem
# puis exporter JWT_PRIVATE_KEY / JWT_PUBLIC_KEY depuis ces fichiers avant de lancer le serveur
```

---

## Grille d'auto-évaluation

| Critère | Acquis si… |
|---|---|
| Preuve avant correction | pour **chaque** trou, tu as prouvé la faille par un appel HTTP **avant** de corriger (token forgé passe, `role` change, `passwordHash` renvoyé, 500 lignes) |
| JWT vérifié | `jwt.verify` avec `algorithms` **en dur** + `audience` + `issuer` + `exp` ; le token forgé **et** `alg:none` tombent en `401` |
| Claims re-copiés | tu ne remets dans `req.user` que `sub`/`role`/`familyId`, jamais le payload brut ; (bonus) RS256 ferme l'algorithm confusion |
| Anti mass assignment | schéma Zod `.strict()`, `400` sur champ inconnu, objet `data` **explicite** — plus de `Object.assign(user, req.body)` |
| Sortie en DTO | `toUserDto`/DTO enfant en allowlist ; aucune réponse ne contient `passwordHash`, `role` interne ni `medicalNotes` |
| Pagination bornée | `page`/`limit` avec **plafond dur** (`?limit=100000` ramené à 100), `skip`/`take` appliqués |
| Rate limiting + taille | `express-rate-limit` renvoie des `429` sous rafale, `express.json({ limit })` borne le body |

**Seuil :** « Acquis » sur JWT vérifié, anti mass assignment et sortie en DTO — les trois trous qui exposent directement les données de mineurs.

---

## Coach — conduite de session

- **Exige la preuve avant la correction, à chaque trou.** Le protocole (a) prouver → (b) corriger → (c) re-prouver est l'objectif pédagogique. Si Sylvain corrige sans avoir vu la faille passer, fais-le revenir forger le token.
- **Point de friction #1 (le plus formateur) :** fais-lui **forger un JWT à la main** (header + payload base64url, signature bidon) avec `role: admin` et l'envoyer. Voir un token bidon passer sur `jwt.decode` ancre pourquoi `verify` + algo imposé est non négociable.
- **Piège à débusquer #1 — `verify` sans `algorithms` :** s'il appelle `jwt.verify` sans imposer l'algo en dur, rappelle l'attaque `alg:none` / algorithm confusion. La liste d'algos est une allowlist, pas un détail.
- **Piège à débusquer #2 — DTO oublié après le fix mass assignment :** il ferme l'écriture (`.strict()`) mais renvoie encore la ligne entière → `passwordHash`/`role` fuient en lecture. Entrée **et** sortie doivent être en allowlist.
- **Piège à débusquer #3 — plafond de pagination absent :** un `limit` validé « nombre » mais sans `max()` laisse `?limit=100000` vider la table. Le plafond est **dur**.
- **Ancrage TribuZen :** ce sont des **fiches d'enfants** avec `medicalNotes`. Chaque trou = fuite de donnée de mineur. Fais-lui nommer l'impact concret, pas juste « CWE ».
- **Si silence / blocage :** attaque les trous **dans l'ordre** (JWT → mass assignment → exposition → pagination/rate limit). Chaque fix est indépendant et vérifiable au curl — la victoire par petits pas débloque.

---

## Variante J+30 (fading)

**Même objectif, contraintes ajoutées** — reproduis le durcissement **de mémoire, en 40 minutes**, sans rouvrir ce corrigé ni le module 08, avec ces ajouts :

1. **Denylist d'algorithmes prouvée** : écris un mini-test manuel (fichier `probe.ts`) qui tente de faire accepter un token `alg:none` **et** un token HS256 forgé avec la clé publique — les deux doivent renvoyer `401`. Montre la sortie au coach.
2. **Rate limiting par compte** : ajoute une limite spécifique (5/15 min) sur un endpoint sensible fictif `POST /api/families/:id/invite`, clé de limite = l'`id` du token (pas l'IP).
3. **Versioning** : monte l'API sous `/api/v2`, et sur `/api/v1` renvoie les en-têtes `Deprecation` + `Sunset`. Explique pourquoi le header seul ne suffit pas (il faut couper).

**Critère de réussite :** les deux tokens malveillants de l'étape 1 échouent, l'endpoint d'invitation renvoie `429` à la 6ᵉ tentative d'un même compte, et aucune réponse ne fuit `passwordHash`/`medicalNotes`.

---

## Application TribuZen

Dans le repo `smaurier/tribuzen` (back-office NestJS), ces protections vivent ici :

```
tribuzen-api/
  src/
    auth/jwt.strategy.ts              ← verify RS256 imposé, aud/iss/exp
    common/guards/throttler.guard.ts  ← @nestjs/throttler → 429
    common/pipes/validation.pipe.ts   ← whitelist:true + forbidNonWhitelisted:true
    common/interceptors/serialize.ts  ← ClassSerializerInterceptor + @Exclude()
    users/dto/update-profile.dto.ts   ← allowlist d'entrée
    children/children.controller.ts   ← pagination bornée
```

**Différences par rapport au lab :**
- L'émission des tokens ne se fait pas dans l'API : c'est le serveur d'auth OIDC (**module 03b**). L'API ne détient que la **clé publique**.
- La validation passe par le `ValidationPipe` global de NestJS (`whitelist`/`forbidNonWhitelisted`) et des DTO décorés, pas par des `safeParse` manuels.
- Le contrôle d'accès par objet (ce parent peut-il voir cette famille ?) est un **Guard d'autorisation** séparé (**module 04**), pas dans ce middleware.

**Commit cible :**
```
feat(api): durcir l'API — verify JWT (RS256, aud/iss/exp), throttling 429, DTO in/out, pagination bornée
```
