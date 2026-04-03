# Module 3 — Authentification

## Objectifs pédagogiques

- Distinguer authentification et autorisation
- Maîtriser le hashing sécurisé des mots de passe
- Comprendre les sessions vs tokens (JWT)
- Implémenter OAuth2/OIDC et MFA
- Prévenir les attaques sur les sessions

---

## 1. Authentification vs Autorisation

| | Authentification | Autorisation |
|---|---|---|
| **Question** | *Qui es-tu ?* | *Qu'as-tu le droit de faire ?* |
| **Moment** | Avant l'autorisation | Après l'authentification |
| **Mécanisme** | Mot de passe, MFA, biométrie | Rôles, permissions, ACL |
| **Erreur HTTP** | 401 Unauthorized | 403 Forbidden |
| **Exemple** | Login avec email/password | Accéder au panneau admin |

```typescript
// Middleware Express — deux étapes distinctes
async function authenticate(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Non authentifié' });

  try {
    req.user = verifyToken(token);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

function authorize(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Accès interdit' });
    }
    next();
  };
}

// Utilisation
app.delete('/api/users/:id', authenticate, authorize('admin'), deleteUser);
```

---

## 2. Mots de passe sécurisés

### 2.1 Pourquoi le hashing est essentiel

| Méthode | Sécurité | Temps de crack |
|---|---|---|
| Texte clair | ❌ Catastrophique | Instantané |
| MD5 | ❌ Cassé | Secondes |
| SHA-256 (sans sel) | ❌ Insuffisant | Minutes (rainbow tables) |
| bcrypt | ✅ Bon | Années |
| argon2id | ✅ Excellent | Années+ |

### 2.2 Hashing avec bcrypt

```typescript
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12; // Coût exponentiel (2^12 itérations)

// Créer un hash
async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
  // Résultat : $2b$12$LJ3m4ys3Lg.Y/7gBSGKjGO...
  //            ↑   ↑  ↑
  //          algo cost  salt+hash
}

// Vérifier un mot de passe
async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
```

### 2.3 Hashing avec argon2 (recommandé)

```typescript
import { hash, verify, argon2id } from 'argon2';

async function hashPassword(password: string): Promise<string> {
  return hash(password, {
    type: argon2id,     // Résistant aux attaques GPU et side-channel
    memoryCost: 65536,  // 64 MB de RAM
    timeCost: 3,        // 3 itérations
    parallelism: 4,     // 4 threads
  });
}

async function verifyPassword(hash: string, password: string): Promise<boolean> {
  return verify(hash, password);
}
```

### 2.4 Salt et Pepper

```
Salt  = valeur aléatoire UNIQUE par mot de passe (stockée avec le hash)
        → Empêche les rainbow tables et le crack en parallèle

Pepper = valeur secrète GLOBALE (stockée en dehors de la BDD)
         → Protège même si la BDD est compromise
```

```typescript
// bcrypt et argon2 gèrent le salt automatiquement
// Le pepper est un secret applicatif supplémentaire

const PEPPER = process.env.PASSWORD_PEPPER!; // Secret hors BDD

async function hashWithPepper(password: string): Promise<string> {
  return hash(password + PEPPER);
}
```

### 2.5 Politique de mots de passe

```typescript
import { z } from 'zod';

const PasswordSchema = z.string()
  .min(12, 'Minimum 12 caractères')
  .max(128, 'Maximum 128 caractères')
  .refine(
    (pw) => /[a-z]/.test(pw) && /[A-Z]/.test(pw) && /[0-9]/.test(pw),
    'Doit contenir minuscules, majuscules et chiffres'
  );

// Vérifier contre les mots de passe compromis (Have I Been Pwned)
async function isPasswordBreached(password: string): Promise<boolean> {
  const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const text = await res.text();
  return text.includes(suffix);
}
```

---

## 3. Sessions vs Tokens

### 3.1 Authentification par session

```
Client                    Serveur
  │                          │
  ├── POST /login ──────────►│
  │   {email, password}      │
  │                          ├── Vérifie credentials
  │                          ├── Crée session en BDD/mémoire
  │◄── Set-Cookie: sid=abc ──┤
  │                          │
  ├── GET /api/me ──────────►│
  │   Cookie: sid=abc        │
  │                          ├── Lookup session "abc"
  │◄── {user: {...}} ───────┤
```

```typescript
import session from 'express-session';
import RedisStore from 'connect-redis';
import { createClient } from 'redis';

const redisClient = createClient();
await redisClient.connect();

app.use(session({
  store: new RedisStore({ client: redisClient }),
  name: '__Host-sid',  // Préfixe __Host- pour cookies sécurisés
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,    // ✅ Inaccessible au JavaScript
    secure: true,      // ✅ HTTPS uniquement
    sameSite: 'lax',   // ✅ Protection CSRF
    maxAge: 3600_000,  // 1 heure
    path: '/',
    domain: '.example.com',
  },
}));
```

### 3.2 Authentification par token (JWT)

```
Client                    Serveur
  │                          │
  ├── POST /login ──────────►│
  │   {email, password}      │
  │                          ├── Vérifie credentials
  │                          ├── Signe un JWT
  │◄── {accessToken: "..."} ─┤
  │                          │
  ├── GET /api/me ──────────►│
  │   Authorization: Bearer ..│
  │                          ├── Vérifie signature JWT
  │◄── {user: {...}} ───────┤
```

### Comparaison

| Critère | Sessions | JWT |
|---|---|---|
| Stockage serveur | Oui (Redis/BDD) | Non (stateless) |
| Scalabilité | Nécessite store partagé | Excellente |
| Révocation | Facile (supprimer la session) | Difficile (attendre l'expiration) |
| Taille | Cookie petit (~32 bytes) | Token plus gros (~1KB) |
| CSRF | Vulnérable (cookie auto) | Protégé (header manuel) |
| XSS | Cookie HttpOnly protège | localStorage vulnérable |

---

## 4. JWT en profondeur

### 4.1 Structure

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE2OTk5OTk5OTksImV4cCI6MTcwMDAwMzU5OX0.
signature_ici

Header (Base64)     .  Payload (Base64)    .  Signature
{                      {
  "alg": "RS256",       "sub": "12345",
  "typ": "JWT"          "name": "John",
}                       "role": "admin",
                        "iat": 1699999999,
                        "exp": 1700003599
                      }
```

### 4.2 Algorithmes de signature

| Algorithme | Type | Clé | Recommandation |
|---|---|---|---|
| HS256 | Symétrique | 1 secret partagé | ✅ Interne, simple |
| RS256 | Asymétrique | Clé privée + publique | ✅ Multi-services |
| ES256 | Asymétrique (ECDSA) | Clé plus petite | ✅ Performant |
| none | Aucune | — | ❌ JAMAIS en production |

### 4.3 Implémentation sécurisée

```typescript
import jwt from 'jsonwebtoken';
import fs from 'node:fs';

// RS256 avec clés asymétriques
const PRIVATE_KEY = fs.readFileSync('./keys/private.pem');
const PUBLIC_KEY = fs.readFileSync('./keys/public.pem');

interface TokenPayload {
  sub: string;
  role: string;
}

function signAccessToken(user: { id: string; role: string }): string {
  return jwt.sign(
    { sub: user.id, role: user.role } satisfies TokenPayload,
    PRIVATE_KEY,
    {
      algorithm: 'RS256',
      expiresIn: '15m',    // Court ! Access token = 15 minutes max
      issuer: 'my-app',
      audience: 'my-app-api',
    }
  );
}

function verifyAccessToken(token: string): TokenPayload {
  return jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],   // ✅ Spécifier EXPLICITEMENT les algos acceptés
    issuer: 'my-app',
    audience: 'my-app-api',
    complete: false,
  }) as TokenPayload;
}
```

### 4.4 Vulnérabilités courantes des JWT

#### Algorithm "none"

```typescript
// ❌ Si le serveur ne vérifie pas l'algorithme, un attaquant peut
// envoyer un token avec alg: "none" et une signature vide

// ✅ TOUJOURS spécifier les algorithmes acceptés
jwt.verify(token, key, { algorithms: ['RS256'] });
// Rejette automatiquement "none" et les algorithmes non listés
```

#### Algorithm confusion (RS256 → HS256)

```typescript
// ❌ L'attaquant change l'algo de RS256 (asymétrique) à HS256 (symétrique)
// et signe avec la CLÉ PUBLIQUE (qui est... publique)

// ✅ Prévention : spécifier explicitement l'algorithme
jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'] }); // Seul RS256 accepté
```

#### Token dans localStorage

```typescript
// ❌ localStorage est accessible au JavaScript → XSS peut voler le token
localStorage.setItem('token', accessToken);

// ✅ Préférer un cookie HttpOnly pour le refresh token
// et garder l'access token en mémoire (variable JS)
let accessToken: string | null = null; // Mémoire volatile, pas localStorage
```

### 4.5 Access Token + Refresh Token

```typescript
// Durées de vie
// Access Token  : court (15 min) — signé, vérifié sans BDD
// Refresh Token : long (7 jours) — stocké en BDD, révocable

function signRefreshToken(userId: string): string {
  const token = crypto.randomBytes(48).toString('hex');
  // Stocker en BDD avec l'userId, la date de création et d'expiration
  return token;
}

// Endpoint de rafraîchissement
app.post('/api/token/refresh', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).json({ error: 'No refresh token' });

  // Vérifier en BDD
  const stored = await db.query(
    'SELECT user_id, expires_at FROM refresh_tokens WHERE token = $1',
    [refreshToken]
  );

  if (!stored.rows[0] || new Date(stored.rows[0].expires_at) < new Date()) {
    return res.status(401).json({ error: 'Refresh token invalide ou expiré' });
  }

  // Token rotation : supprimer l'ancien, créer un nouveau
  await db.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);

  const user = await findUserById(stored.rows[0].user_id);
  const newAccessToken = signAccessToken(user);
  const newRefreshToken = signRefreshToken(user.id);

  res.cookie('refreshToken', newRefreshToken, {
    httpOnly: true, secure: true, sameSite: 'strict', maxAge: 7 * 86400_000,
  });
  res.json({ accessToken: newAccessToken });
});
```

---

## 5. OAuth2 et OpenID Connect

### 5.1 OAuth2 — Les 4 flows

| Flow | Cas d'usage | Sécurité |
|---|---|---|
| **Authorization Code** | Apps web avec backend | ✅ Recommandé |
| **Authorization Code + PKCE** | SPA, apps mobiles | ✅ Recommandé |
| **Client Credentials** | Machine-to-machine | ✅ Sûr (pas d'utilisateur) |
| **Implicit** | (obsolète) | ❌ Déprécié |

### 5.2 Authorization Code Flow avec PKCE

```typescript
import crypto from 'node:crypto';

// Étape 1 : Générer le PKCE challenge
function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
  return { verifier, challenge };
}

// Étape 2 : Rediriger l'utilisateur vers le provider
app.get('/auth/login', (req, res) => {
  const { verifier, challenge } = generatePKCE();
  // Stocker le verifier en session (ou cookie sécurisé)
  req.session.pkceVerifier = verifier;

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.OAUTH_CLIENT_ID!,
    redirect_uri: 'https://myapp.com/auth/callback',
    scope: 'openid profile email',
    state: crypto.randomBytes(16).toString('hex'), // Anti-CSRF
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });

  res.redirect(`https://auth.provider.com/authorize?${params}`);
});

// Étape 3 : Échanger le code contre des tokens
app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;

  // Vérifier le state anti-CSRF
  // ...

  const tokenResponse = await fetch('https://auth.provider.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: String(code),
      redirect_uri: 'https://myapp.com/auth/callback',
      client_id: process.env.OAUTH_CLIENT_ID!,
      code_verifier: req.session.pkceVerifier, // Preuve PKCE
    }),
  });

  const tokens = await tokenResponse.json();
  // tokens.access_token, tokens.id_token, tokens.refresh_token
});
```

### 5.3 OpenID Connect (OIDC)

OIDC est une **couche d'identité** au-dessus d'OAuth2. Il ajoute :

- Le **ID Token** (JWT) contenant les infos de l'utilisateur
- L'endpoint **UserInfo** pour récupérer le profil
- La **discovery** (`.well-known/openid-configuration`)

```typescript
// Vérifier un ID Token OIDC
import { jwtVerify, createRemoteJWKSet } from 'jose';

const JWKS = createRemoteJWKSet(
  new URL('https://auth.provider.com/.well-known/jwks.json')
);

async function verifyIdToken(idToken: string) {
  const { payload } = await jwtVerify(idToken, JWKS, {
    issuer: 'https://auth.provider.com',
    audience: process.env.OAUTH_CLIENT_ID!,
  });
  return payload; // { sub, email, name, ... }
}
```

---

## 6. Multi-Factor Authentication (MFA)

### 6.1 TOTP (Time-based One-Time Password)

```typescript
import { authenticator } from 'otplib';
import QRCode from 'qrcode';

// Étape 1 : Générer un secret pour l'utilisateur
async function enableMFA(user: User) {
  const secret = authenticator.generateSecret();
  // Stocker le secret (chiffré) en BDD
  await db.query(
    'UPDATE users SET mfa_secret = $1 WHERE id = $2',
    [encrypt(secret), user.id]
  );

  // Générer l'URI pour l'app authenticator
  const otpauth = authenticator.keyuri(user.email, 'MonApp', secret);
  const qrCodeUrl = await QRCode.toDataURL(otpauth);
  return { qrCodeUrl, secret }; // Afficher le QR code à l'utilisateur
}

// Étape 2 : Vérifier le code TOTP
function verifyTOTP(secret: string, token: string): boolean {
  return authenticator.verify({ token, secret });
  // Vérifie avec une fenêtre de ±30 secondes
}

// Étape 3 : Login avec MFA
app.post('/api/login', async (req, res) => {
  const { email, password, totpCode } = req.body;

  const user = await findUser(email);
  if (!user || !await verifyPassword(user.passwordHash, password)) {
    return res.status(401).json({ error: 'Identifiants invalides' });
  }

  if (user.mfaEnabled) {
    if (!totpCode) {
      return res.status(200).json({ requiresMFA: true });
    }
    const secret = decrypt(user.mfaSecret);
    if (!verifyTOTP(secret, totpCode)) {
      return res.status(401).json({ error: 'Code MFA invalide' });
    }
  }

  const token = signAccessToken(user);
  res.json({ accessToken: token });
});
```

### 6.2 WebAuthn / Passkeys

WebAuthn utilise la cryptographie asymétrique avec le matériel de l'appareil (Touch ID, Windows Hello, clés FIDO2).

```typescript
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const rpName = 'Mon Application';
const rpID = 'myapp.com';
const origin = 'https://myapp.com';

// Enregistrement d'un passkey
app.post('/api/webauthn/register-options', authenticate, async (req, res) => {
  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: req.user.id,
    userName: req.user.email,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  req.session.challenge = options.challenge;
  res.json(options);
});
```

---

## 7. Gestion de sessions — Attaques et protections

### 7.1 Session Fixation

L'attaquant fixe un ID de session connu et attend que la victime s'authentifie avec.

```typescript
// ✅ Régénérer l'ID de session après l'authentification
app.post('/api/login', async (req, res) => {
  // ... vérification des credentials ...

  // Régénérer la session pour éviter la fixation
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Erreur serveur' });
    req.session.userId = user.id;
    req.session.save(() => {
      res.json({ message: 'Connecté' });
    });
  });
});
```

### 7.2 Session Hijacking

Vol du cookie de session via XSS ou interception réseau.

```typescript
// ✅ Protections multiples
app.use(session({
  cookie: {
    httpOnly: true,    // Pas accessible en JavaScript
    secure: true,      // HTTPS uniquement
    sameSite: 'strict', // Pas envoyé dans les requêtes cross-site
  },
}));

// ✅ Lier la session à l'empreinte du client
app.use((req, res, next) => {
  const fingerprint = `${req.headers['user-agent']}:${req.ip}`;
  if (req.session.fingerprint && req.session.fingerprint !== fingerprint) {
    req.session.destroy(() => {
      res.status(401).json({ error: 'Session invalidée' });
    });
    return;
  }
  req.session.fingerprint = fingerprint;
  next();
});
```

### 7.3 Timeouts

```typescript
const SESSION_IDLE_TIMEOUT = 30 * 60 * 1000;    // 30 minutes d'inactivité
const SESSION_ABSOLUTE_TIMEOUT = 8 * 3600_000;   // 8 heures max

app.use((req, res, next) => {
  if (!req.session.userId) return next();

  const now = Date.now();

  // Timeout absolu — la session expire même si active
  if (now - req.session.createdAt > SESSION_ABSOLUTE_TIMEOUT) {
    return req.session.destroy(() => {
      res.status(401).json({ error: 'Session expirée' });
    });
  }

  // Timeout d'inactivité
  if (now - req.session.lastActivity > SESSION_IDLE_TIMEOUT) {
    return req.session.destroy(() => {
      res.status(401).json({ error: 'Session expirée par inactivité' });
    });
  }

  req.session.lastActivity = now;
  next();
});
```

---

## 8. Récapitulatif

### Règles essentielles

1. **Hasher** les mots de passe avec argon2id ou bcrypt — jamais MD5/SHA
2. **JWT** : spécifier les algorithmes, durée courte, rotation des refresh tokens
3. **Cookies** : HttpOnly, Secure, SameSite=Strict
4. **Token storage** : access token en mémoire, refresh token en cookie HttpOnly
5. **MFA** : activer pour les fonctions sensibles (paiement, admin)
6. **Sessions** : régénérer après login, idle + absolute timeouts
7. **OAuth2** : utiliser Authorization Code + PKCE pour les SPA

---

> **Prochain module** : Autorisation — contrôler ce que les utilisateurs peuvent faire.
