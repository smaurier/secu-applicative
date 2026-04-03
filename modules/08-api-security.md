# Module 08 — Sécurité des APIs

## Objectifs pédagogiques

- Sécuriser une API REST : rate limiting, validation, pagination
- Comprendre les vulnérabilités spécifiques à GraphQL
- Distinguer API Keys et Bearer Tokens
- Mettre en place throttling, circuit breakers et idempotency
- Utiliser un API Gateway comme couche de sécurité
- Documenter les contraintes de sécurité avec OpenAPI

---

## 1. Sécurité des APIs REST

### 1.1 Rate Limiting

Le rate limiting protège contre les abus, le brute force, et les attaques par déni de service.

#### express-rate-limit

```typescript
import rateLimit from 'express-rate-limit';

// Rate limiter global
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                   // 100 requêtes par fenêtre
  standardHeaders: true,      // Retourne les en-têtes RateLimit-*
  legacyHeaders: false,
  message: { error: 'Trop de requêtes, réessayez plus tard' },
});

// Rate limiter strict pour l'authentification
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,                     // Seulement 5 tentatives
  skipSuccessfulRequests: true,
  message: { error: 'Trop de tentatives de connexion' },
});

app.use('/api/', globalLimiter);
app.use('/api/auth/login', authLimiter);
```

#### Algorithme Sliding Window

Le sliding window offre un contrôle plus précis que la fenêtre fixe :

```typescript
import { RedisStore } from 'rate-limit-redis';
import { createClient } from 'redis';

const redisClient = createClient({ url: process.env.REDIS_URL });

const slidingWindowLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  store: new RedisStore({
    sendCommand: (...args: string[]) => redisClient.sendCommand(args),
  }),
});
```

### 1.2 Validation des inputs

**Ne jamais faire confiance aux données entrantes.** Validez tout au niveau de l'API.

#### Avec Zod

```typescript
import { z } from 'zod';

const CreateUserSchema = z.object({
  email: z.string().email().max(255),
  name: z.string().min(2).max(100).trim(),
  age: z.number().int().min(13).max(150).optional(),
  role: z.enum(['user', 'admin']).default('user'),
});

type CreateUserInput = z.infer<typeof CreateUserSchema>;

app.post('/api/users', (req, res) => {
  const result = CreateUserSchema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json({
      error: 'Validation failed',
      details: result.error.flatten(),
    });
  }

  // result.data est typé et validé
  createUser(result.data);
});
```

#### Avec class-validator (NestJS)

```typescript
import { IsEmail, IsString, MinLength, MaxLength, IsOptional, IsInt, Min, Max } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  @MaxLength(255)
  email: string;

  @IsString()
  @MinLength(2)
  @MaxLength(100)
  name: string;

  @IsOptional()
  @IsInt()
  @Min(13)
  @Max(150)
  age?: number;
}
```

### 1.3 Pagination et limites de taille

Empêchez les requêtes qui retourneraient des volumes massifs de données :

```typescript
const PaginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  sortBy: z.enum(['createdAt', 'name', 'email']).default('createdAt'),
  order: z.enum(['asc', 'desc']).default('desc'),
});

app.get('/api/users', (req, res) => {
  const params = PaginationSchema.parse(req.query);
  const offset = (params.page - 1) * params.limit;

  // Limiter le body des requêtes
  // app.use(express.json({ limit: '1mb' }));
});
```

### 1.4 Versioning et deprecation sécurisée

```typescript
// Versionner explicitement les APIs
app.use('/api/v1', v1Router);
app.use('/api/v2', v2Router);

// En-tête de deprecation
app.use('/api/v1', (req, res, next) => {
  res.setHeader('Deprecation', 'true');
  res.setHeader('Sunset', 'Sat, 01 Jan 2027 00:00:00 GMT');
  res.setHeader('Link', '</api/v2>; rel="successor-version"');
  next();
});
```

### 1.5 Filtrage des champs de réponse

Ne jamais exposer les données internes ou sensibles :

```typescript
interface User {
  id: string;
  email: string;
  name: string;
  passwordHash: string;  // JAMAIS dans la réponse
  internalNotes: string; // JAMAIS dans la réponse
  createdAt: Date;
}

// DTO de réponse — seulement les champs publics
interface UserResponse {
  id: string;
  email: string;
  name: string;
  createdAt: string;
}

function toUserResponse(user: User): UserResponse {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    createdAt: user.createdAt.toISOString(),
  };
}

app.get('/api/users/:id', async (req, res) => {
  const user = await findUser(req.params.id);
  // Retourner SEULEMENT les champs autorisés
  res.json(toUserResponse(user));
});
```

---

## 2. Sécurité GraphQL spécifique

GraphQL introduit des vulnérabilités uniques que REST n'a pas.

### 2.1 Query Depth Limiting

Un attaquant peut créer des requêtes imbriquées à l'infini :

```graphql
# Requête malveillante — nesting profond
query {
  user(id: "1") {
    friends {
      friends {
        friends {
          friends {
            friends {
              # ... à l'infini → surcharge le serveur
            }
          }
        }
      }
    }
  }
}
```

Solution avec `graphql-depth-limit` :

```typescript
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [depthLimit(5)], // Profondeur max de 5
});
```

### 2.2 Query Complexity Analysis

Limiter le coût total d'une requête :

```typescript
import { createComplexityLimitRule } from 'graphql-validation-complexity';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  validationRules: [
    createComplexityLimitRule(1000, {
      // Coûts personnalisés par champ
      scalarCost: 1,
      objectCost: 10,
      listFactor: 20,
    }),
  ],
});
```

### 2.3 Désactiver l'introspection en production

L'introspection révèle tout le schéma de votre API :

```typescript
import { ApolloServer } from '@apollo/server';

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: process.env.NODE_ENV !== 'production',
});
```

### 2.4 Batching Attacks

GraphQL permet d'envoyer plusieurs requêtes en une seule :

```json
[
  { "query": "mutation { login(email: \"a@b.com\", password: \"password1\") { token } }" },
  { "query": "mutation { login(email: \"a@b.com\", password: \"password2\") { token } }" },
  { "query": "mutation { login(email: \"a@b.com\", password: \"password3\") { token } }" }
]
```

Solution : limiter le nombre de requêtes par batch :

```typescript
const server = new ApolloServer({
  typeDefs,
  resolvers,
  allowBatchedHttpRequests: false, // Désactiver le batching
});
```

### 2.5 Field-level Authorization

```typescript
const resolvers = {
  User: {
    email: (parent: User, _args: unknown, context: Context) => {
      // Seul l'utilisateur lui-même ou un admin peut voir l'email
      if (context.user.id === parent.id || context.user.role === 'admin') {
        return parent.email;
      }
      return null;
    },
    passwordHash: () => {
      throw new Error('Ce champ n\'est pas accessible');
    },
  },
};
```

---

## 3. API Keys vs Bearer Tokens

| Aspect | API Key | Bearer Token (JWT) |
|---|---|---|
| **Usage** | Identifier l'application cliente | Identifier l'utilisateur |
| **Durée** | Longue (mois/années) | Courte (minutes/heures) |
| **Transmission** | Header `X-API-Key` ou query param | Header `Authorization: Bearer` |
| **Révocation** | Régénérer la clé | Attendre l'expiration ou blacklist |
| **Granularité** | Niveau application | Niveau utilisateur |
| **Sécurité** | Moins sécurisé (longue durée) | Plus sécurisé (courte durée + refresh) |

```typescript
// Middleware pour API Key
function apiKeyAuth(req: Request, res: Response, next: NextFunction) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || typeof apiKey !== 'string') {
    return res.status(401).json({ error: 'API key required' });
  }

  // Comparer avec un hash, pas en texte brut
  const client = await findClientByKeyHash(hashApiKey(apiKey));
  if (!client) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  req.client = client;
  next();
}

// Middleware pour Bearer Token
function bearerAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Bearer token required' });
  }

  const token = authHeader.slice(7);
  try {
    const payload = verifyJwt(token);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}
```

---

## 4. Throttling et Circuit Breakers

### Throttling

Le throttling est différent du rate limiting : il **ralentit** les requêtes au lieu de les bloquer.

```typescript
import Bottleneck from 'bottleneck';

// Limiter à 10 requêtes par seconde vers un service externe
const limiter = new Bottleneck({
  maxConcurrent: 5,
  minTime: 100, // 100ms entre chaque requête
});

async function callExternalAPI(data: unknown): Promise<Response> {
  return limiter.schedule(() => fetch('https://external-api.com/data', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  }));
}
```

### Circuit Breaker

Le circuit breaker protège contre les pannes en cascade :

```typescript
import CircuitBreaker from 'opossum';

const options = {
  timeout: 3000,       // Timeout par requête
  errorThresholdPercentage: 50, // Ouvre le circuit à 50% d'erreurs
  resetTimeout: 30000, // Réessaie après 30 secondes
};

const breaker = new CircuitBreaker(callExternalAPI, options);

breaker.on('open', () => console.warn('Circuit OUVERT — service indisponible'));
breaker.on('halfOpen', () => console.info('Circuit SEMI-OUVERT — test en cours'));
breaker.on('close', () => console.info('Circuit FERMÉ — service rétabli'));

// Utilisation
app.get('/api/external-data', async (req, res) => {
  try {
    const result = await breaker.fire(req.query);
    res.json(result);
  } catch {
    res.status(503).json({ error: 'Service temporairement indisponible' });
  }
});
```

---

## 5. Idempotency Keys

Pour les mutations (POST, PUT), un problème réseau peut entraîner un doublon. Les clés d'idempotence garantissent qu'une opération n'est exécutée qu'une seule fois :

```typescript
// Le client envoie une clé unique
// POST /api/payments
// Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000

app.post('/api/payments', async (req, res) => {
  const idempotencyKey = req.headers['idempotency-key'];

  if (!idempotencyKey || typeof idempotencyKey !== 'string') {
    return res.status(400).json({ error: 'Idempotency-Key header required' });
  }

  // Vérifier si cette opération a déjà été traitée
  const existing = await cache.get(`idempotency:${idempotencyKey}`);
  if (existing) {
    return res.status(200).json(JSON.parse(existing));
  }

  // Exécuter l'opération
  const result = await processPayment(req.body);

  // Stocker le résultat (TTL de 24h)
  await cache.set(`idempotency:${idempotencyKey}`, JSON.stringify(result), 'EX', 86400);

  res.status(201).json(result);
});
```

---

## 6. Logging des accès API

```typescript
import { randomUUID } from 'crypto';

// Middleware de logging structuré
app.use((req, res, next) => {
  const requestId = randomUUID();
  const startTime = Date.now();

  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);

  res.on('finish', () => {
    const duration = Date.now() - startTime;
    console.log(JSON.stringify({
      requestId,
      timestamp: new Date().toISOString(),
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration,
      userAgent: req.headers['user-agent'],
      ip: req.ip,
      userId: req.user?.id ?? 'anonymous',
    }));
  });

  next();
});
```

> **Règle** : ne jamais logger les tokens, mots de passe, ou données personnelles sensibles.

---

## 7. API Gateway comme couche de sécurité

Un API Gateway centralise les préoccupations transversales de sécurité :

```
┌──────────┐     ┌─────────────────┐     ┌──────────────┐
│  Client   │────→│   API Gateway   │────→│  Microservice│
│           │←────│                 │←────│              │
└──────────┘     │  • Auth         │     └──────────────┘
                 │  • Rate Limit   │     ┌──────────────┐
                 │  • CORS         │────→│  Microservice│
                 │  • Logging      │←────│              │
                 │  • WAF          │     └──────────────┘
                 └─────────────────┘
```

Fonctionnalités de sécurité d'un API Gateway :
- **Authentification** : valide les tokens avant de transmettre
- **Rate limiting** : limite par client, par route, par IP
- **WAF** (Web Application Firewall) : bloque les payloads malveillants
- **Transformation** : masque les headers internes
- **Circuit breaking** : protège les services surchargés

---

## 8. OpenAPI et documentation des contraintes de sécurité

Documentez les exigences de sécurité dans votre spécification OpenAPI :

```yaml
openapi: 3.0.3
info:
  title: Mon API Sécurisée
  version: 1.0.0

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    apiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key

  schemas:
    CreateUser:
      type: object
      required: [email, name]
      properties:
        email:
          type: string
          format: email
          maxLength: 255
        name:
          type: string
          minLength: 2
          maxLength: 100
        age:
          type: integer
          minimum: 13
          maximum: 150

security:
  - bearerAuth: []

paths:
  /api/users:
    post:
      summary: Créer un utilisateur
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateUser'
      responses:
        '201':
          description: Utilisateur créé
        '400':
          description: Validation échouée
        '401':
          description: Non authentifié
        '429':
          description: Rate limit atteint
```

---

## 9. Résumé

| Mesure | Objectif |
|---|---|
| Rate limiting | Protéger contre les abus et le brute force |
| Validation des inputs | Empêcher les injections et données invalides |
| Pagination | Éviter les surcharges mémoire |
| Filtrage des réponses | Ne pas exposer les données sensibles |
| GraphQL depth/complexity | Empêcher les requêtes abusives |
| Circuit breaker | Protéger contre les pannes en cascade |
| Idempotency keys | Éviter les doublons de mutations |
| API Gateway | Centraliser la sécurité transversale |

---

## Exercice pratique

1. Configurez `express-rate-limit` avec un store Redis pour le sliding window
2. Implémentez la validation des inputs avec Zod sur un endpoint POST
3. Ajoutez le logging structuré avec `X-Request-ID`
4. Si vous utilisez GraphQL, ajoutez le depth limiting et désactivez l'introspection
5. Implémentez les idempotency keys pour un endpoint de paiement

---

## Ressources

- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit)
- [Zod Documentation](https://zod.dev/)
- [Apollo Server Security](https://www.apollographql.com/docs/apollo-server/security/)
- [OpenAPI Specification](https://spec.openapis.org/oas/latest.html)
