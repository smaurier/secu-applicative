# Module 07 — CORS (Cross-Origin Resource Sharing)

## Objectifs pédagogiques

- Comprendre la Same-Origin Policy et ses implications
- Maîtriser le mécanisme CORS et les requêtes preflight
- Configurer CORS correctement dans Express et NestJS
- Debugger les erreurs CORS courantes
- Comprendre les interactions entre CORS, cookies et credentials

---

## 1. Same-Origin Policy (SOP)

La **Same-Origin Policy** est une politique de sécurité fondamentale du navigateur. Elle interdit à un script d'une origine d'accéder aux ressources d'une autre origine.

### Définition d'une origine

Une origine est définie par le triplet : **protocole + hôte + port**.

```
https://example.com:443  →  protocole: https, hôte: example.com, port: 443

Même origine :
  https://example.com/page1  ↔  https://example.com/page2       ✅

Origines différentes :
  https://example.com        ↔  http://example.com               ❌ (protocole)
  https://example.com        ↔  https://api.example.com          ❌ (hôte)
  https://example.com        ↔  https://example.com:8080         ❌ (port)
```

### Exceptions à la SOP

Certaines ressources sont chargées cross-origin **sans restriction** :

- `<img src="...">` — images
- `<script src="...">` — scripts (mais pas l'accès au contenu)
- `<link rel="stylesheet" href="...">` — CSS
- `<video>`, `<audio>` — médias
- `<iframe>` — encadrement (soumis à X-Frame-Options / frame-ancestors)

> ⚠️ La SOP s'applique aux **requêtes programmatiques** (`fetch`, `XMLHttpRequest`), pas au chargement de ressources via HTML.

---

## 2. Qu'est-ce que CORS

**CORS** (Cross-Origin Resource Sharing) est un mécanisme qui permet à un serveur d'indiquer quelles origines sont autorisées à accéder à ses ressources via des requêtes programmatiques.

C'est un **assouplissement contrôlé** de la Same-Origin Policy.

```
┌─────────────┐         ┌──────────────────┐
│  Frontend   │  fetch   │   API Backend    │
│  port 5173  │ ───────→ │   port 3000      │
│             │ ←─────── │                  │
│             │  CORS    │  Access-Control- │
│             │  headers │  Allow-Origin    │
└─────────────┘         └──────────────────┘
```

---

## 3. Requêtes simples vs Preflight

### 3.1 Requête simple

Une requête est considérée "simple" si elle remplit **toutes** ces conditions :

- Méthode : `GET`, `HEAD`, ou `POST`
- En-têtes : seulement `Accept`, `Accept-Language`, `Content-Language`, `Content-Type`
- Content-Type : seulement `application/x-www-form-urlencoded`, `multipart/form-data`, ou `text/plain`

Pour une requête simple, le navigateur envoie directement la requête avec l'en-tête `Origin` :

```
GET /api/data HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
```

Le serveur répond avec les en-têtes CORS :

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.example.com
```

### 3.2 Requête Preflight

Si la requête ne remplit pas les conditions d'une requête simple, le navigateur envoie d'abord une requête **OPTIONS** (preflight) :

```
OPTIONS /api/data HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Content-Type, Authorization
```

Le serveur doit répondre avec les autorisations :

```
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 86400
```

Si la preflight est acceptée, le navigateur envoie ensuite la vraie requête.

```
                    ┌─────────┐
                    │ Browser │
                    └────┬────┘
                         │
              ┌──────────┴───────────┐
              │  La requête est-elle  │
              │     "simple" ?       │
              └──────────┬───────────┘
                    ╱          ╲
                 Oui            Non
                  │              │
          Envoie direct    OPTIONS preflight
          avec Origin      │
                  │        │ Réponse OK ?
                  │        │     │
                  │      Oui    Non
                  │        │     │
                  ▼        ▼     ▼
              Requête   Requête  ERREUR
              réelle    réelle   CORS
```

---

## 4. En-têtes CORS

### 4.1 Access-Control-Allow-Origin

```
Access-Control-Allow-Origin: https://app.example.com   # Origine spécifique
Access-Control-Allow-Origin: *                           # Toute origine
```

> ⚠️ `*` ne fonctionne **PAS** avec `credentials: 'include'`. Vous devez spécifier l'origine exacte.

### 4.2 Access-Control-Allow-Methods

```
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH
```

Spécifie les méthodes HTTP autorisées pour les requêtes cross-origin.

### 4.3 Access-Control-Allow-Headers

```
Access-Control-Allow-Headers: Content-Type, Authorization, X-Request-ID
```

Spécifie les en-têtes personnalisés autorisés dans la requête.

### 4.4 Access-Control-Allow-Credentials

```
Access-Control-Allow-Credentials: true
```

Autorise l'envoi de cookies et d'informations d'authentification cross-origin.

**Règle critique** : quand `Access-Control-Allow-Credentials: true`, `Access-Control-Allow-Origin` **ne peut pas** être `*`. Il faut une origine spécifique.

### 4.5 Access-Control-Max-Age

```
Access-Control-Max-Age: 86400
```

Durée (en secondes) pendant laquelle le navigateur peut mettre en cache la réponse preflight. Réduit le nombre de requêtes OPTIONS.

### 4.6 Access-Control-Expose-Headers

Par défaut, le JavaScript côté client ne peut lire que certains en-têtes de réponse. Pour exposer des en-têtes supplémentaires :

```
Access-Control-Expose-Headers: X-Total-Count, X-Request-ID
```

---

## 5. Configuration dans Express

### Avec le middleware `cors`

```typescript
import express from 'express';
import cors from 'cors';

const app = express();

// Configuration basique — origine unique
app.use(cors({
  origin: 'https://app.example.com',
}));

// Configuration avec plusieurs origines autorisées
const allowedOrigins = [
  'https://app.example.com',
  'https://admin.example.com',
];

app.use(cors({
  origin: (origin, callback) => {
    // Permettre les requêtes sans origin (ex: mobile apps, curl)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Origine non autorisée par CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400,
  exposedHeaders: ['X-Total-Count'],
}));
```

### Configuration manuelle (sans middleware)

```typescript
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  next();
});
```

> **Important** : ajoutez `Vary: Origin` quand l'origine change dynamiquement, sinon les caches pourraient servir la mauvaise valeur.

---

## 6. Configuration dans NestJS

### Via `enableCors()` dans le bootstrap

```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: ['https://app.example.com', 'https://admin.example.com'],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400,
  });

  await app.listen(3000);
}
bootstrap();
```

### Avec un origin dynamique (callback)

```typescript
app.enableCors({
  origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') ?? [];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
});
```

---

## 7. Erreurs CORS courantes et debugging

### Erreur typique dans la console

```
Access to fetch at 'https://api.example.com/data' from origin 'https://app.example.com'
has been blocked by CORS policy: No 'Access-Control-Allow-Origin' header is present
on the requested resource.
```

### Causes fréquentes

| Symptôme | Cause probable | Solution |
|---|---|---|
| No Access-Control-Allow-Origin | Le serveur n'envoie pas l'en-tête | Configurer CORS côté serveur |
| Preflight échoue (405) | Le serveur ne gère pas OPTIONS | Ajouter un handler OPTIONS |
| Credentials avec `*` | `Allow-Origin: *` + credentials | Spécifier l'origine exacte |
| Header non autorisé | En-tête personnalisé non listé | Ajouter dans `Allow-Headers` |
| Méthode non autorisée | PUT/DELETE non autorisé | Ajouter dans `Allow-Methods` |

### Debugging avec les DevTools

1. Onglet **Network** → filtrer par la requête échouée
2. Chercher la requête **OPTIONS** (preflight)
3. Vérifier les **en-têtes de réponse** CORS
4. Comparer avec les en-têtes de **requête** (`Access-Control-Request-*`)

```typescript
// Côté client — vérifier ce qui est envoyé
fetch('https://api.example.com/data', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer token123',
  },
  credentials: 'include', // Nécessaire pour les cookies
  body: JSON.stringify({ key: 'value' }),
});
```

---

## 8. CORS et Cookies

### SameSite et credentials

Pour que les cookies soient envoyés en cross-origin :

1. **Côté client** : `credentials: 'include'` dans fetch
2. **Côté serveur** : `Access-Control-Allow-Credentials: true`
3. **Cookie** : `SameSite=None; Secure`

```typescript
// Côté serveur — configuration du cookie
res.cookie('session', 'abc123', {
  httpOnly: true,
  secure: true,         // Obligatoire avec SameSite=None
  sameSite: 'none',     // Permet l'envoi cross-origin
  domain: '.example.com',
  maxAge: 3600000,
});
```

### Tableau SameSite

| SameSite | Requête cross-origin | Requête same-site | Navigation (lien) |
|---|---|---|---|
| `Strict` | ❌ Cookie non envoyé | ✅ | ❌ |
| `Lax` (défaut) | ❌ Cookie non envoyé | ✅ | ✅ (GET top-level) |
| `None` + `Secure` | ✅ Cookie envoyé | ✅ | ✅ |

---

## 9. Sécurité : CORS n'est PAS une protection côté serveur

> **Point crucial** : CORS est une politique **du navigateur**. Un attaquant utilisant `curl`, Postman, ou un script serveur n'est **pas soumis** à CORS.

```bash
# curl ignore complètement CORS
curl https://api.example.com/data -H "Authorization: Bearer stolen-token"
```

CORS protège **les utilisateurs du navigateur** contre les scripts malveillants sur d'autres sites. Il ne remplace **jamais** :

- L'authentification et l'autorisation côté serveur
- La validation des tokens
- Le rate limiting
- La vérification des permissions

---

## 10. Alternatives à CORS

### Reverse Proxy

Un reverse proxy (Nginx, Traefik) fait transiter les requêtes API par le même domaine :

```
app.example.com/         → Frontend (port 5173)
app.example.com/api/     → Backend (port 3000)
```

```nginx
# Configuration Nginx
server {
    listen 443 ssl;
    server_name app.example.com;

    location / {
        proxy_pass http://frontend:5173;
    }

    location /api/ {
        proxy_pass http://backend:3000/;
    }
}
```

Plus de problème CORS car tout est sur la **même origine**.

### API Gateway

Un API Gateway (Kong, AWS API Gateway) centralise les accès et peut gérer CORS de manière uniforme pour tous les microservices.

### Proxy de développement (Vite)

En développement, configurez un proxy dans Vite :

```typescript
// vite.config.ts
import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
});
```

---

## 11. Résumé

| Concept | Point clé |
|---|---|
| SOP | Le navigateur bloque les requêtes cross-origin par défaut |
| CORS | Mécanisme pour autoriser des origines spécifiques |
| Preflight | Requête OPTIONS automatique pour les requêtes non simples |
| Credentials | Nécessite origine spécifique (pas `*`) + `SameSite=None` |
| Sécurité | CORS protège le navigateur, pas le serveur |

---

## Exercice pratique

1. Créez un frontend (Vite) sur le port 5173 et un backend Express sur le port 3000
2. Faites un `fetch` cross-origin et observez l'erreur CORS dans les DevTools
3. Ajoutez la configuration CORS côté serveur
4. Testez avec `credentials: 'include'` et un cookie `SameSite=None`
5. Configurez un proxy Vite pour éliminer le besoin de CORS en développement

---

## Ressources

- [MDN — CORS](https://developer.mozilla.org/fr/docs/Web/HTTP/CORS)
- [MDN — Same-Origin Policy](https://developer.mozilla.org/fr/docs/Web/Security/Same-origin_policy)
- [Fetch Living Standard — CORS Protocol](https://fetch.spec.whatwg.org/#http-cors-protocol)
- [web.dev — Cross-origin resource sharing](https://web.dev/articles/cross-origin-resource-sharing)
