<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Lab 03 — Durcir un flux d'authentification (DÉFENSIF)

> **Outcome :** à la fin, tu sais transformer un endpoint de login fragile en un flux durci — hachage **argon2id**, comparaison en temps constant, message **anti-énumération**, **rate limiting**, session régénérée, et second facteur **TOTP**.
> **Vrai outil :** Node.js + TypeScript + `argon2`, `otplib`, `express-rate-limit` (paquets npm réels, exécutés avec `tsx`). **Aucun harnais simulé.**
> **Angle :** **DÉFENSIF** — on durcit *ton* endpoint, on n'attaque aucun système tiers.
> **Feedback :** le coach valide en session (pas de test-runner auto-correcteur).

---

## Énoncé

On te livre le endpoint de login vulnérable du back-office **TribuZen** (données de familles/enfants — sensible). Il « marche » mais cumule quatre failles. **Ta mission : le durcir**, sans changer son contrat public (mêmes routes, mêmes champs).

### Le point de départ vulnérable

```typescript
// login-vulnerable.ts — NE PAS déployer. C'est la CIBLE à durcir.
import crypto from 'node:crypto'
import express from 'express'

const app = express()
app.use(express.json())

// "Base" en mémoire pour le lab (en vrai : Prisma/Postgres).
const users = [
  // mot de passe = "correct horse battery staple", haché en SHA-256 (à remplacer !)
  {
    id: 'u1',
    email: 'parent@tribuzen.app',
    passwordHash: crypto.createHash('sha256').update('correct horse battery staple').digest('hex'),
    mfaEnabled: false,
    mfaSecret: null as string | null,
  },
]

app.post('/api/login', (req, res) => {
  const { email, password } = req.body
  const user = users.find((u) => u.email === email)

  if (!user) {
    return res.status(404).json({ error: `Aucun compte pour ${email}` }) // FAILLE 1
  }
  const hash = crypto.createHash('sha256').update(password).digest('hex')  // FAILLE 2
  if (hash !== user.passwordHash) {                                        // FAILLE 2 (===)
    return res.status(401).json({ error: 'Mot de passe incorrect' })       // FAILLE 1
  }
  res.json({ token: user.id }) // FAILLE 4 : id en clair, aucune session ; FAILLE 3 : 0 anti-brute-force

  void app // évite le tree-shake dans le starter
})

app.listen(3000, () => console.log('login vulnérable sur :3000'))
```

### Ce que tu dois produire

Un fichier `login-hardened.ts` qui corrige les **quatre failles** :

1. **Anti-énumération** — même message (`Identifiants invalides`) et même code (**401**) que le compte existe ou non, **en temps constant** (hash factice si l'utilisateur n'existe pas).
2. **Hachage sûr** — remplacer SHA-256 par **argon2id** (paramètres OWASP : mémoire ≥ 19456 KiB, timeCost 2, parallelism 1) et vérifier avec `argon2.verify` (jamais `===`).
3. **Anti-brute-force** — un `express-rate-limit` sur `/api/login` (5 tentatives / 15 min).
4. **Session + MFA** — si `mfaEnabled`, renvoyer `{ mfaRequired: true, challengeId }` au lieu d'ouvrir la session ; sinon poser une session régénérée. Ajouter un endpoint `/api/login/totp` qui vérifie un code `otplib` avant d'ouvrir la session.

**Pas de gap-fill.** Tu écris `login-hardened.ts` complet à partir du starter ci-dessous.

### Starter minimal

```bash
npm init -y
npm pkg set type=module          # ESM : requis pour le top-level await du corrigé
npm i express argon2 otplib express-rate-limit express-session
npm i -D tsx @types/express @types/express-session
```

```typescript
// login-hardened.ts — starter (à compléter)
import express from 'express'
import argon2 from 'argon2'
import { authenticator } from 'otplib'
import rateLimit from 'express-rate-limit'
import session from 'express-session'

const app = express()
app.use(express.json())

// TODO 1 : configurer express-session (cookie __Host-* : httpOnly, secure, sameSite)
// TODO 2 : pré-calculer un DUMMY_HASH pour égaliser le timing
// TODO 3 : semer un utilisateur dont le passwordHash est en argon2id (pas SHA-256)
// TODO 4 : POST /api/login  → rate limit + verify temps constant + branche MFA + session régénérée
// TODO 5 : POST /api/login/totp → vérifier le code TOTP puis ouvrir la session

app.listen(3000, () => console.log('login durci sur :3000'))
```

---

## Étapes (en friction)

1. **Sème un hash argon2id** — remplace le SHA-256 du starter par `await argon2.hash('correct horse battery staple', { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 })`. Observe la chaîne `$argon2id$v=19$m=19456,t=2,p=1$...` : sel et paramètres sont embarqués.
2. **Égalise le timing** — pré-calcule `DUMMY_HASH` une fois au démarrage. Dans le handler, fais **toujours** un `argon2.verify` (sur le vrai hash si l'utilisateur existe, sinon sur `DUMMY_HASH`) avant de répondre.
3. **Message générique** — pour `pas d'utilisateur` ET `mauvais mot de passe`, renvoie exactement `res.status(401).json({ error: 'Identifiants invalides' })`.
4. **Rate limit** — monte `rateLimit({ windowMs: 15 * 60 * 1000, limit: 5 })` en middleware de la route login.
5. **Branche MFA** — si `user.mfaEnabled`, renvoie `{ mfaRequired: true, challengeId: user.id }` sans ouvrir de session.
6. **Session régénérée** — sinon, `req.session.regenerate(...)` puis stocke `userId` + `createdAt` (anti-fixation).
7. **Endpoint TOTP** — `/api/login/totp` : `authenticator.verify({ token, secret })`, échec → 401 générique, succès → session régénérée. (Pour tester : active `mfaEnabled`, mets un `mfaSecret = authenticator.generateSecret()`, et génère un code avec `authenticator.generate(secret)`.)
8. **Vérifie de tête** : un email inexistant et un mauvais mot de passe donnent-ils la **même** réponse et **~le même temps** ? (mesure avec `console.time`).

---

## Corrigé complet commenté

```typescript
// login-hardened.ts — corrigé
import express from 'express'
import argon2 from 'argon2'
import { authenticator } from 'otplib'
import rateLimit from 'express-rate-limit'
import session from 'express-session'

const app = express()
app.use(express.json())

// --- Session serveur : cookie durci ---
// __Host- impose Secure + Path=/ + pas de Domain (cookie lié à l'origine exacte).
// En local sans HTTPS, secure:true empêchera l'envoi du cookie : on garde le nom __Host-
// pour la prod et on note qu'en dev on testerait derrière un proxy TLS.
app.use(session({
  name: '__Host-sid',
  secret: process.env.SESSION_SECRET ?? 'dev-only-change-me',
  resave: false,
  saveUninitialized: false,          // pas de session avant login
  cookie: {
    httpOnly: true,                  // un XSS ne peut pas lire le cookie
    secure: true,                    // HTTPS uniquement
    sameSite: 'lax',                 // atténue le CSRF
    maxAge: 1000 * 60 * 60,          // 1 h
    path: '/',
  },
}))

// Étend le type de session pour TypeScript.
declare module 'express-session' {
  interface SessionData { userId?: string; createdAt?: number }
}

// --- Hash factice : égalise le timing quand l'email n'existe pas ---
// Pré-calculé UNE fois au démarrage — même coût que le verify d'un vrai hash.
const DUMMY_HASH = await argon2.hash('timing-equalizer-not-a-real-password', {
  type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1,
})

// --- "Base" en mémoire : le mot de passe est haché en argon2id, PAS en SHA-256 ---
const users = [
  {
    id: 'u1',
    email: 'parent@tribuzen.app',
    passwordHash: await argon2.hash('correct horse battery staple', {
      type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1,
    }),
    mfaEnabled: true,
    // En vrai : secret CHIFFRÉ en base. Ici en clair pour la lisibilité du lab.
    mfaSecret: authenticator.generateSecret(),
  },
]

// --- Anti-brute-force : 5 tentatives / 15 min par IP ---
// (À compléter en prod par un verrou SUR LE COMPTE, à backoff exponentiel.)
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5 })

// --- POST /api/login ---
app.post('/api/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body as { email?: string; password?: string }
  const user = users.find((u) => u.email === email)

  // FAILLE 2 corrigée : verify argon2 en temps constant.
  // FAILLE 1 corrigée : on hache TOUJOURS (DUMMY_HASH si pas d'utilisateur) → même timing.
  let ok = false
  if (user) {
    ok = await argon2.verify(user.passwordHash, password ?? '')
  } else {
    await argon2.verify(DUMMY_HASH, password ?? '') // travail équivalent, résultat ignoré
  }

  if (!user || !ok) {
    // Message + code IDENTIQUES dans les deux cas → pas d'énumération.
    return res.status(401).json({ error: 'Identifiants invalides' })
  }

  // FAILLE 3/4 corrigées : MFA d'abord, sinon session régénérée.
  if (user.mfaEnabled) {
    // On n'ouvre PAS la session tant que le 2e facteur n'est pas validé.
    return res.status(200).json({ mfaRequired: true, challengeId: user.id })
  }

  return openSession(req, res, user.id)
})

// --- POST /api/login/totp : second facteur ---
app.post('/api/login/totp', loginLimiter, async (req, res) => {
  const { challengeId, code } = req.body as { challengeId?: string; code?: string }
  const user = users.find((u) => u.id === challengeId)

  // Message générique même si l'utilisateur/secret est absent.
  if (!user?.mfaSecret || !authenticator.verify({ token: code ?? '', secret: user.mfaSecret })) {
    return res.status(401).json({ error: 'Identifiants invalides' })
  }
  return openSession(req, res, user.id)
})

// --- Helper : régénère l'ID de session (anti-fixation) puis lie l'utilisateur ---
function openSession(req: express.Request, res: express.Response, userId: string) {
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Erreur serveur' })
    req.session.userId = userId
    req.session.createdAt = Date.now()
    req.session.save(() => res.json({ ok: true }))
  })
}

app.listen(3000, () => console.log('login durci sur :3000'))
```

**Pourquoi ce corrigé est correct :**
- **Anti-énumération en temps constant** — la branche « pas d'utilisateur » exécute quand même un `argon2.verify` sur `DUMMY_HASH`, donc email inexistant et mauvais mot de passe coûtent le même temps et renvoient le même `401 { error: 'Identifiants invalides' }`.
- **Hachage** — argon2id aux paramètres OWASP, sel + params embarqués ; vérification via `argon2.verify` (temps constant), jamais `===`.
- **Anti-brute-force** — `loginLimiter` sur les deux endpoints d'authentification (login *et* TOTP).
- **Session** — `regenerate()` avant de poser `userId` tue la session fixation ; cookie `__Host-` `HttpOnly`/`Secure`/`SameSite`.
- **MFA** — la session n'est **jamais** ouverte tant que le second facteur n'a pas répondu.

---

## Variante J+30 (fading)

**Même objectif, contraintes ajoutées, sans rouvrir ce corrigé ni le module :**

1. Reproduis `login-hardened.ts` **de mémoire, en 30 minutes**.
2. Ajoute un **verrou de compte à backoff exponentiel** : après N échecs sur *le même email*, refuse pendant `2^(N-seuil)` secondes (indépendamment de l'IP). Garde le rate limiting IP en plus.
3. Ajoute un endpoint **`/api/password/forgot`** qui génère un token de reset **haché** en base, à usage unique, TTL 30 min, et renvoie **toujours** `{ ok: true }` (message générique, jamais « email inconnu »).

**Critère de réussite :** un email inexistant, un mauvais mot de passe et un `/password/forgot` sur un email inconnu sont **indistinguables** (même réponse), et le verrou de compte se déclenche indépendamment de l'IP.

---

## Application TribuZen

Dans `smaurier/tribuzen` (back-office NestJS), ce flux vit ici :

```
tribuzen-api/
  src/
    auth/
      auth.service.ts        ← hashPassword (argon2id), verify temps constant, DUMMY_HASH
      auth.controller.ts     ← POST /login, /login/totp, /password/forgot, /password/reset
      session.config.ts      ← cookie __Host-sid, régénération après login
      totp.service.ts        ← otplib, secret chiffré, codes de secours hachés
    common/guards/
      rate-limit.guard.ts    ← throttling IP + verrou compte à backoff exponentiel
```

**Différences par rapport au lab :**
- La « base » en mémoire devient **Prisma/Postgres** ; `mfaSecret` est **chiffré** au repos (pas en clair).
- Express `session` devient l'intégration NestJS (`@nestjs/passport` ou session middleware) avec store **Redis**.
- Le rate limiting passe en **guard** NestJS (`@nestjs/throttler`) + verrou compte persistant.
- Le reset password (variante J+30) devient un vrai service avec email transactionnel.

**Commit cible :**
```
feat(auth): durcir le login — argon2id, timing constant anti-énumération, rate limit, session régénérée, TOTP
```
