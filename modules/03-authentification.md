---
titre: Authentification — hachage, sessions, MFA, durcissement
cours: 14-securite-applicative
notions: ["sessions vs tokens", "hachage argon2id / bcrypt", "jamais MD5/SHA seul", "politique de mot de passe (OWASP)", "MFA / TOTP", "gestion de session sécurisée", "protection brute-force", "reset password sûr", "user enumeration"]
outcomes:
  - "sait hacher un mot de passe avec argon2id (ou bcrypt) aux paramètres OWASP 2026 et expliquer pourquoi MD5/SHA seul est disqualifié"
  - "sait choisir entre session serveur et token, et durcir chaque option (cookie __Host-, régénération, timeouts)"
  - "sait appliquer une politique de mot de passe OWASP (longueur, pas de rotation, blocage des mots de passe compromis)"
  - "sait ajouter un second facteur TOTP et durcir un flux d'auth contre le brute-force et l'énumération d'utilisateurs"
  - "sait concevoir un reset password sûr (token aléatoire à durée de vie courte, message générique)"
prerequis:
  - "Introduction sécurité — modèle de menace, CIA, defense in depth (module 00)"
  - "OWASP Top 10 2021 — A07 Identification and Authentication Failures (module 01)"
  - "Injection & échappement — requêtes paramétrées, validation d'entrée (module 02)"
next: 03b-oidc-pkce-client
libs: []
tribuzen: back-office TribuZen — authentification des parents/familles (login, hachage, session, MFA, reset)
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Authentification — hachage, sessions, MFA, durcissement

> **Outcomes — tu sauras FAIRE :** hacher un mot de passe aux paramètres OWASP 2026, choisir et durcir une stratégie de session/token, appliquer une politique de mot de passe moderne, ajouter un second facteur TOTP, et fermer les portes du brute-force, de l'énumération d'utilisateurs et d'un reset password fragile.
> **Difficulté :** :star::star::star:
>
> **Angle : DÉFENSIF.** On montre les failles pour les **comprendre et les corriger** dans TON code, jamais pour attaquer un tiers.
>
> **Portée :** ce module couvre l'**authentification classique par mot de passe** (le facteur « ce que tu sais ») plus le second facteur TOTP. La délégation d'identité **OAuth2 / OIDC + PKCE** est le **module 03b**. **WebAuthn / passkeys** (le facteur « ce que tu possèdes », sans mot de passe) est le **module 03c**. L'**autorisation** (« qu'as-tu le droit de faire ? ») est le **module 04** — ici on répond seulement à « qui es-tu ? ».

## 1. Cas concret d'abord

Tu reprends le back-office TribuZen. Un parent se connecte pour gérer les activités de ses enfants — donc des **données de mineurs**, l'enjeu le plus sensible de l'app. Un collègue a livré ce endpoint de login. Il « marche » en démo.

```typescript
// POST /api/login — AVANT durcissement. NE PAS copier en prod.
import crypto from 'node:crypto'

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body

  const user = await db.user.findUnique({ where: { email } })
  if (!user) {
    return res.status(404).json({ error: `Aucun compte pour ${email}` }) // (1)
  }

  // (2) SHA-256 « parce que c'est cryptographique »
  const hash = crypto.createHash('sha256').update(password).digest('hex')
  if (hash !== user.passwordHash) {
    return res.status(401).json({ error: 'Mot de passe incorrect' })      // (3)
  }

  // (4) le serveur renvoie l'id utilisateur en clair comme « jeton »
  res.json({ token: user.id })
})
```

**Quatre trous que ce module va boucher :**

1. **Énumération d'utilisateurs** — `404 « Aucun compte pour X »` dit à un attaquant quels emails existent. Message + code HTTP doivent être **identiques** que le compte existe ou non.
2. **Hachage disqualifié** — `SHA-256` est un hash *rapide* : un GPU teste des milliards de candidats par seconde. Pour un mot de passe il faut un hash *lent et paramétrable* (argon2id, bcrypt). Et il n'y a **pas de sel**, donc deux parents avec le même mot de passe ont le même hash.
3. **Aucune limite de tentatives** — rien n'empêche 10 000 essais/seconde sur un compte.
4. **« Jeton » = id en clair** — devinable, non signé, non expirable, non révocable. Ce n'est pas de l'authentification.

À la fin du module, ce endpoint hache en argon2id, renvoie un message générique en temps constant, limite le brute-force, pose un cookie de session `__Host-`, et propose un second facteur. C'est le fil rouge du lab.

---

## 2. Théorie complète, concise

### 2.1 Authentification ≠ autorisation (cadrage)

- **Authentification (authN)** — « qui es-tu ? ». Échec → **401**.
- **Autorisation (authZ)** — « as-tu le droit ? ». Échec → **403**.

Ce module ne traite que l'authN. L'authZ (rôles, RBAC, IDOR) est le module 04. Les confondre est une cause classique de faille.

### 2.2 Hacher un mot de passe : lent, salé, paramétrable

Un mot de passe ne se **chiffre jamais** (le chiffrement est réversible) : on le **hache** avec une fonction conçue pour être **lente et gourmande en mémoire**, de sorte qu'une fuite de base ne permette pas de retrouver les mots de passe par force brute.

**Disqualifiés pour un mot de passe :** MD5, SHA-1, SHA-256, SHA-512 **seuls**. Ce sont des hash *rapides* — parfaits pour l'intégrité d'un fichier, catastrophiques pour un mot de passe. OWASP : « les algorithmes de hachage rapides comme SHA-256 ne conviennent pas au stockage de mots de passe car ils permettent à un attaquant un très grand nombre d'essais rapidement ».

**Recommandations OWASP (Password Storage Cheat Sheet, vérifié 2026-07) :**

| Algorithme | Quand | Paramètres minimaux OWASP |
|---|---|---|
| **argon2id** | 1er choix | mémoire **≥ 19 MiB**, itérations **2**, parallélisme **1** |
| **scrypt** | si argon2 indisponible | coût CPU/mémoire `N = 2^17`, `r = 8`, `p = 1` |
| **bcrypt** | legacy / systèmes anciens | facteur de travail (cost) **≥ 10** ; **limite d'entrée 72 octets** |
| **PBKDF2** | contrainte FIPS-140 | PBKDF2-HMAC-SHA256 **600 000** itérations |

> Ce sont des **planchers**. Sur un serveur moderne, on monte les paramètres tant que le hachage reste ~raisonnable (viser un login sous ~1 s). Argon2id à 19 MiB est un minimum ; 64 MiB est courant.

```typescript
// argon2id — 1er choix (paquet: argon2)
import argon2 from 'argon2'

async function hashPassword(plain: string): Promise<string> {
  return argon2.hash(plain, {
    type: argon2.argon2id,  // hybride : résiste GPU (data-dependent) ET side-channel
    memoryCost: 19456,      // 19 MiB, en KiB — plancher OWASP ; monter si le serveur suit
    timeCost: 2,            // itérations
    parallelism: 1,
  })
  // argon2 GÉNÈRE et EMBARQUE le sel + les paramètres dans la chaîne renvoyée :
  //   $argon2id$v=19$m=19456,t=2,p=1$<sel base64>$<hash base64>
}

async function verifyPassword(hashed: string, plain: string): Promise<boolean> {
  // Comparaison en temps constant, fournie par la lib. Ne JAMAIS comparer avec ===.
  return argon2.verify(hashed, plain)
}
```

```typescript
// bcrypt — alternative si argon2 indisponible (paquet: bcrypt)
import bcrypt from 'bcrypt'

const COST = 12 // ≥ 10 (OWASP) ; 12 est un bon défaut 2026

async function hashPassword(plain: string): Promise<string> {
  // ⚠️ bcrypt IGNORE au-delà de 72 octets. Pré-hacher en SHA-256 base64
  //    AVANT bcrypt si tu veux accepter les longs passphrases sans troncature silencieuse.
  return bcrypt.hash(plain, COST) // sel généré et embarqué : $2b$12$...
}
```

**Sel vs poivre (pepper) :**
- **Sel (salt)** — aléatoire, **unique par mot de passe**, stocké *avec* le hash. argon2/bcrypt le gèrent seuls. Il casse les rainbow tables et empêche de cracker deux comptes identiques d'un coup.
- **Poivre (pepper)** — secret **global**, stocké *hors* de la base (variable d'env, KMS). Optionnel, en défense en profondeur : si seule la base fuit, les hash restent inattaquables sans le poivre. Implémenté idéalement via un HMAC de la lib, pas par simple concaténation.

### 2.3 Politique de mot de passe : ce qui a changé

Les règles « 8 caractères, 1 majuscule, 1 chiffre, 1 symbole, changement tous les 90 jours » sont **obsolètes** (elles poussent aux `Password1!` et aux post-it). Politique OWASP / NIST actuelle :

- **Longueur** : minimum **8** si MFA activé, **15** sans MFA. Maximum **≥ 64** pour autoriser les passphrases.
- **Composition** : **autoriser tous les caractères** (unicode, espaces inclus). Pas d'obligation de classes de caractères.
- **Pas de troncature silencieuse** au-delà du max.
- **Bloquer les mots de passe compromis** — vérifier contre une base de fuites (Pwned Passwords, via **k-anonymity** : on n'envoie que les 5 premiers caractères du SHA-1). Optionnel : mètre de robustesse (zxcvbn).
- **Pas de rotation périodique** imposée — on ne force le changement qu'en cas de compromission avérée.
- **MFA** = la meilleure défense (stoppe ~99,9 % des compromissions de compte selon les analyses citées par OWASP).

### 2.4 Sessions vs tokens

Après vérification du mot de passe, il faut **maintenir** l'identité entre les requêtes (HTTP est sans état). Deux familles :

**Session serveur (stateful)** — le serveur génère un **identifiant de session opaque et aléatoire**, le stocke (Redis/BDD), et le renvoie dans un **cookie**. À chaque requête il fait un lookup.

```typescript
import session from 'express-session'
import { RedisStore } from 'connect-redis'

app.use(session({
  store: new RedisStore({ client: redisClient }),
  name: '__Host-sid',              // préfixe __Host- : impose Secure + Path=/ + pas de Domain
  secret: process.env.SESSION_SECRET!, // clé de signature du cookie ; secret hors code
  resave: false,
  saveUninitialized: false,        // pas de session avant login → RGPD-friendly, moins de bruit
  cookie: {
    httpOnly: true,                // inaccessible au JS → un XSS ne peut pas lire le cookie
    secure: true,                  // HTTPS uniquement
    sameSite: 'lax',               // atténue le CSRF ; 'strict' pour les actions sensibles
    maxAge: 1000 * 60 * 60,        // 1 h
    path: '/',
  },
}))
```

**Token (stateless)** — le serveur signe un **JWT** que le client renvoie dans l'en-tête `Authorization: Bearer`. Le serveur vérifie la **signature** sans lookup. Détails et pièges JWT (algorithme `none`, algorithm confusion RS256→HS256, stockage) → **module 08 (API security)**. Le flux OAuth/OIDC qui émet ces tokens → **module 03b**.

| Critère | Session serveur | JWT (token) |
|---|---|---|
| État serveur | oui (store) | non (stateless) |
| Révocation immédiate | facile (supprimer la session) | difficile (attendre l'expiration ou denylist) |
| Passage à l'échelle | store partagé requis | naturel |
| Transport par défaut | cookie (auto-envoyé → attention CSRF) | header (manuel → pas de CSRF auto) |
| Risque de vol | cookie `HttpOnly` protège du XSS | `localStorage` exposé au XSS |

**Défaut raisonnable pour une app web classique comme TribuZen : session serveur + cookie `__Host-` `HttpOnly`.** Le JWT brille surtout en microservices / API multi-clients.

### 2.5 Durcir la session

- **Régénérer l'ID après login** (`req.session.regenerate`) → tue la **session fixation** (l'attaquant ne peut pas pré-fixer un ID que la victime authentifiera).
- **Double timeout** : **inactivité** (~15–30 min) *et* **absolu** (~8 h) — la session meurt même active.
- **Régénérer aussi lors d'une élévation de privilège** (ex. entrée dans une zone admin).
- **Invalider côté serveur au logout** (détruire la session, pas seulement supprimer le cookie).
- **Cookie** : `HttpOnly` + `Secure` + `SameSite` + préfixe `__Host-`.

### 2.6 Protection anti-brute-force et anti-énumération

- **Verrouillage sur le compte** (pas sur l'IP seule, qui tourne) : seuil de tentatives, fenêtre d'observation, durée de blocage — idéalement **backoff exponentiel** (1 s, 2 s, 4 s…).
- **Rate limiting / throttling** au niveau IP + compte, **CAPTCHA** après quelques échecs.
- **Messages génériques en temps constant** : même réponse (« Identifiants invalides »), même code (401), même latence, que l'email existe ou non. Attention à la **différence de timing** : si un email inexistant répond instantanément et un email existant après un `argon2.verify` de 300 ms, l'attaquant énumère à la montre. Parade : hacher un **hash factice** même quand l'utilisateur n'existe pas.
- Laisser le **« mot de passe oublié » fonctionner même pendant un verrouillage**, sinon on crée un déni de service.

### 2.7 Reset password sûr

Le « mot de passe oublié » est une **porte d'authentification** à part entière — souvent le maillon faible.

- **Token aléatoire** (≥ 32 octets, CSPRNG), **à usage unique**, **à durée de vie courte** (~15–60 min).
- **Ne stocker que le hash du token** en base (comme un mot de passe) : si la base fuit, les tokens ne sont pas rejouables.
- **Message générique** : « Si cette adresse existe, un email a été envoyé » — jamais « cet email n'existe pas » (énumération).
- **Ne jamais** envoyer le mot de passe (ni un nouveau mot de passe) par email.
- **Invalider les sessions existantes** après un reset réussi, et notifier l'utilisateur par email du changement.

---

## 3. Worked examples

### Exemple 1 — Endpoint de login durci (TribuZen)

On reprend le endpoint du §1 et on bouche les quatre trous.

```typescript
// POST /api/login — APRÈS durcissement
import argon2 from 'argon2'
import rateLimit from 'express-rate-limit'

// Hash factice pré-calculé une fois : sert à égaliser le timing quand l'email n'existe pas.
const DUMMY_HASH = await argon2.hash('timing-equalizer-not-a-real-password')

// Limiteur : 5 tentatives / 15 min par IP (compléter par un verrou sur le compte).
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5 })

app.post('/api/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body
  const user = await db.user.findUnique({ where: { email } })

  // (2) Toujours faire un verify argon2 — même sans utilisateur — pour un timing constant.
  //     On ne révèle jamais lequel des deux (email/mot de passe) était faux.
  const ok = user
    ? await argon2.verify(user.passwordHash, password)
    : (await argon2.verify(DUMMY_HASH, password), false)

  if (!user || !ok) {
    // (1) Message + code IDENTIQUES quel que soit le cas → pas d'énumération.
    return res.status(401).json({ error: 'Identifiants invalides' })
  }

  // (3) MFA : si activé, on ne pose PAS encore la session — on exige le code TOTP (voir Exemple 2).
  if (user.mfaEnabled) {
    return res.status(200).json({ mfaRequired: true, challengeId: user.id })
  }

  // (4) Session serveur : régénérer l'ID (anti-fixation) puis y lier l'utilisateur.
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Erreur serveur' })
    req.session.userId = user.id
    req.session.createdAt = Date.now()
    req.session.save(() => res.json({ ok: true }))
  })
})
```

Ce qui a changé : hachage argon2id vérifié en temps constant, message/HTTP génériques, rate limiting, session régénérée dans un cookie `__Host-` `HttpOnly`, et branche MFA.

### Exemple 2 — Second facteur TOTP

TOTP (Time-based One-Time Password, RFC 6238) : un secret partagé une fois, l'app d'authentification (Google Authenticator, Aegis…) et le serveur en dérivent le même code à 6 chiffres toutes les 30 s.

```typescript
import { authenticator } from 'otplib'
import QRCode from 'qrcode'

// --- Activation : générer un secret, l'afficher en QR code ---
async function enableTotp(user: { id: string; email: string }) {
  const secret = authenticator.generateSecret()
  // Stocker le secret CHIFFRÉ (pas en clair) — c'est une clé, pas une donnée publique.
  await db.user.update({ where: { id: user.id }, data: { mfaSecret: encrypt(secret) } })

  const otpauth = authenticator.keyuri(user.email, 'TribuZen', secret)
  const qrDataUrl = await QRCode.toDataURL(otpauth) // affiché à l'utilisateur pour scan
  return { qrDataUrl }
}

// --- Vérification à la connexion (après mot de passe OK, cf. Exemple 1) ---
app.post('/api/login/totp', async (req, res) => {
  const { challengeId, code } = req.body
  const user = await db.user.findUnique({ where: { id: challengeId } })
  if (!user?.mfaSecret) return res.status(401).json({ error: 'Identifiants invalides' })

  const secret = decrypt(user.mfaSecret)
  // otplib tolère une petite dérive d'horloge (fenêtre de ±1 pas par défaut).
  if (!authenticator.verify({ token: code, secret })) {
    return res.status(401).json({ error: 'Code invalide' }) // limiter aussi cet endpoint !
  }

  // Seulement MAINTENANT on ouvre la session.
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Erreur serveur' })
    req.session.userId = user.id
    req.session.createdAt = Date.now()
    req.session.save(() => res.json({ ok: true }))
  })
})
```

> **Codes de secours** : générer ~10 codes à usage unique (stockés hachés) à l'activation, pour ne pas verrouiller un parent qui perd son téléphone. Rate-limiter l'endpoint TOTP au même titre que le login.

---

## 4. Pièges & misconceptions

### PIÈGE #1 — « SHA-256 est cryptographique, donc sûr pour un mot de passe »
Faux. SHA-256 est *rapide et sûr pour l'intégrité*, mais un hash de mot de passe doit être **lent et gourmand en mémoire**. Correct : argon2id / bcrypt / scrypt / PBKDF2. Ajouter un `salt` à SHA-256 ne suffit pas : le sel casse les rainbow tables mais pas le brute-force GPU.

### PIÈGE #2 — Comparer les hash avec `===`
`if (hash === user.passwordHash)` est vulnérable au **timing** et, avec argon2/bcrypt, tout simplement faux (le hash embarque sel + paramètres). Utiliser la fonction dédiée : `argon2.verify(...)`, `bcrypt.compare(...)` — comparaison en temps constant intégrée.

### PIÈGE #3 — Messages d'erreur trop bavards → énumération
`404 « email inconnu »` vs `401 « mot de passe faux »` révèle quels comptes existent. Même faille au reset (« cet email n'existe pas ») et à l'inscription (« email déjà pris »). Correct : **un seul message générique**, **même code HTTP**, **même timing** (hash factice si pas d'utilisateur).

### PIÈGE #4 — Oublier de régénérer la session après login
Réutiliser l'ID de session pré-login expose à la **session fixation**. Toujours `req.session.regenerate()` juste après l'authentification (et à l'élévation de privilège).

### PIÈGE #5 — bcrypt et la troncature silencieuse à 72 octets
bcrypt **ignore silencieusement** tout ce qui dépasse 72 octets : deux passphrases longues partageant les 72 premiers octets ont le même hash. Parade : pré-hacher (SHA-256 → base64) avant bcrypt, ou préférer argon2id qui n'a pas cette limite.

### PIÈGE #6 — Confondre le poivre (pepper) et le sel
Le **sel** est unique par mot de passe et stocké avec le hash (géré par la lib). Le **poivre** est un secret **global** stocké **hors base**. Mettre le poivre en base à côté du hash le rend inutile — tout fuit ensemble.

### PIÈGE #7 — Forcer la rotation périodique et une composition complexe
La politique « change ton mot de passe tous les 90 jours + 1 symbole obligatoire » est **contre-productive** (OWASP/NIST l'ont abandonnée) : elle produit des variantes prévisibles. Correct : longueur généreuse, tous caractères autorisés, blocage des mots de passe compromis, MFA.

---

## 5. Ancrage TribuZen

L'authentification est la **porte d'entrée du back-office TribuZen**, qui manipule des données de mineurs — donc le durcissement n'est pas optionnel.

Où ça vit dans `smaurier/tribuzen` (back-office NestJS) :

```
tribuzen-api/
  src/
    auth/
      auth.service.ts        ← hashPassword (argon2id), verify en temps constant, DUMMY_HASH
      auth.controller.ts     ← POST /login, /login/totp, /password/forgot, /password/reset
      session.config.ts      ← cookie __Host-sid, HttpOnly/Secure/SameSite, régénération
      totp.service.ts        ← enableTotp, verify (otplib), codes de secours hachés
      password-policy.ts     ← longueur ≥ 8 (MFA) / 15 (sans), check Pwned Passwords (k-anonymity)
    common/
      guards/rate-limit.ts   ← throttling login + verrou compte (backoff exponentiel)
```

Points d'ancrage concrets :
- **Parents/familles** : login email + argon2id, session `__Host-sid`, MFA proposée dès l'inscription.
- **Reset** : token 32 octets haché en base, TTL 30 min, message générique, invalidation des sessions au succès.
- **Anti-abus** : rate limiting sur `/login` et `/login/totp`, verrou de compte à backoff exponentiel.
- **Autorisation** (qui voit quelle famille) → **module 04**, pas ici.

---

## 6. Points clés

1. Un mot de passe se **hache** (argon2id 1er choix : ≥ 19 MiB / 2 / 1), jamais avec MD5/SHA seul (hash *rapides* = disqualifiés).
2. Le **sel** (unique, avec le hash) est géré par la lib ; le **poivre** (global, hors base) est une défense en profondeur optionnelle.
3. **Vérifier** un mot de passe via `argon2.verify` / `bcrypt.compare` (temps constant), jamais `===`.
4. Politique moderne : longueur ≥ 8 (MFA) ou 15 (sans), tous caractères, **pas de rotation forcée**, blocage des mots de passe compromis.
5. Session serveur + cookie `__Host-` `HttpOnly`/`Secure`/`SameSite` = défaut sain pour une app web ; **régénérer l'ID après login** (anti-fixation) + double timeout.
6. Anti-brute-force : verrou **sur le compte** à backoff exponentiel + rate limiting + CAPTCHA ; anti-énumération : message générique, même code HTTP, **même timing**.
7. **MFA/TOTP** = meilleure défense (~99,9 % des compromissions stoppées) ; secret chiffré, endpoint TOTP rate-limité, codes de secours hachés.
8. Reset sûr : token aléatoire à usage unique, **haché** en base, TTL court, message générique, jamais le mot de passe par email, sessions invalidées au succès.

---

## 7. Seeds Anki

```
Pourquoi SHA-256 est-il disqualifié pour stocker un mot de passe ?|C'est un hash RAPIDE : un GPU teste des milliards de candidats/seconde. Un mot de passe exige un hash LENT et gourmand en mémoire (argon2id, bcrypt, scrypt, PBKDF2). Ajouter un sel ne suffit pas.
Quels sont les paramètres minimaux OWASP 2026 pour argon2id ?|Mémoire ≥ 19 MiB, itérations (timeCost) = 2, parallélisme = 1. Ce sont des planchers : on monte tant que le login reste ~1 s.
Différence entre sel (salt) et poivre (pepper) ?|Sel : aléatoire, UNIQUE par mot de passe, stocké AVEC le hash (géré par argon2/bcrypt), casse les rainbow tables. Poivre : secret GLOBAL stocké HORS base (env/KMS), défense en profondeur si la base fuit.
Pourquoi ne jamais comparer deux hash de mot de passe avec === ?|=== fuit par timing et, avec argon2/bcrypt, est faux car le hash embarque sel+paramètres. Utiliser argon2.verify / bcrypt.compare (comparaison temps constant).
Comment un endpoint de login évite-t-il l'énumération d'utilisateurs ?|Même message ("Identifiants invalides"), même code HTTP (401) et même TIMING que le compte existe ou non — d'où le hachage d'un hash factice quand l'utilisateur n'existe pas.
Qu'est-ce que la session fixation et comment la contrer ?|L'attaquant fixe un ID de session que la victime authentifie ensuite. Parade : régénérer l'ID de session (req.session.regenerate) juste après le login et à toute élévation de privilège.
Politique de mot de passe OWASP/NIST moderne en 4 points ?|Longueur ≥ 8 (avec MFA) ou 15 (sans) et max ≥ 64 ; tous caractères autorisés (unicode, espaces) ; PAS de rotation périodique forcée ; bloquer les mots de passe compromis (Pwned Passwords).
Que stocke-t-on en base pour un token de reset password sûr ?|Seulement le HASH du token (pas le token en clair), token aléatoire ≥ 32 octets CSPRNG à usage unique, TTL court (~15-60 min). Message générique + invalidation des sessions au succès.
Piège bcrypt à connaître sur la longueur d'entrée ?|bcrypt ignore silencieusement au-delà de 72 octets → deux longues passphrases identiques sur 72 octets ont le même hash. Parade : pré-hacher en SHA-256/base64 avant bcrypt, ou utiliser argon2id.
```

---

## Pont vers le lab

> Lab associé : `labs/lab-03-authentification/README.md`. Exercice **défensif** : durcir un flux de login TribuZen fragile (hachage argon2id, session régénérée, message anti-énumération en temps constant, rate limiting, second facteur TOTP). Vrai outil, pas de harnais simulé. Corrigé commenté + variante J+30.
