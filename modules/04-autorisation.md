# Module 4 — Autorisation

## Objectifs pédagogiques

- Connaître les modèles d'autorisation : RBAC, ABAC, ACL
- Implémenter RBAC et ABAC dans un contexte Node.js/NestJS
- Comprendre et prévenir les failles de Broken Access Control
- Mettre en place le Row-Level Security en PostgreSQL
- Centraliser l'autorisation dans une architecture distribuée

---

## 1. Modèles d'autorisation

### Vue d'ensemble

```
  ┌──────────────────────────────────────────────┐
  │              Qui peut faire quoi ?            │
  └──────────────┬───────────────────────────────┘
                 │
    ┌────────────┼────────────┬──────────────┐
    ▼            ▼            ▼              ▼
  RBAC         ABAC         ACL          ReBAC
  (Rôles)    (Attributs)  (Listes)    (Relations)
```

---

## 2. RBAC — Role-Based Access Control

### 2.1 Concepts

- **Utilisateur** : entité authentifiée
- **Rôle** : ensemble nommé de permissions (admin, editor, viewer)
- **Permission** : droit d'effectuer une action sur une ressource
- **Hiérarchie** : un rôle peut hériter des permissions d'un autre

```typescript
// Modèle de données RBAC
interface Role {
  name: string;
  permissions: Permission[];
  inherits?: Role[];
}

interface Permission {
  resource: string;  // 'article', 'user', 'report'
  action: string;    // 'create', 'read', 'update', 'delete'
}

const roles: Record<string, Role> = {
  viewer: {
    name: 'viewer',
    permissions: [
      { resource: 'article', action: 'read' },
    ],
  },
  editor: {
    name: 'editor',
    permissions: [
      { resource: 'article', action: 'create' },
      { resource: 'article', action: 'update' },
    ],
    inherits: [roles.viewer], // Hérite de viewer
  },
  admin: {
    name: 'admin',
    permissions: [
      { resource: 'article', action: 'delete' },
      { resource: 'user', action: 'create' },
      { resource: 'user', action: 'read' },
      { resource: 'user', action: 'update' },
      { resource: 'user', action: 'delete' },
    ],
    inherits: [roles.editor], // Hérite de editor (et transitif: viewer)
  },
};
```

### 2.2 Implémentation Express avec middleware

```typescript
// Middleware RBAC pour Express
function hasPermission(resource: string, action: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const userRole = req.user?.role;
    if (!userRole) {
      return res.status(401).json({ error: 'Non authentifié' });
    }

    if (checkRolePermission(userRole, resource, action)) {
      return next();
    }

    return res.status(403).json({ error: 'Permission refusée' });
  };
}

function checkRolePermission(
  roleName: string,
  resource: string,
  action: string
): boolean {
  const role = roles[roleName];
  if (!role) return false;

  // Vérifier les permissions directes
  const hasDirectPermission = role.permissions.some(
    (p) => p.resource === resource && p.action === action
  );
  if (hasDirectPermission) return true;

  // Vérifier les rôles hérités (récursivement)
  return role.inherits?.some((parent) =>
    checkRolePermission(parent.name, resource, action)
  ) ?? false;
}

// Utilisation sur les routes
app.get('/api/articles',
  authenticate,
  hasPermission('article', 'read'),
  listArticles
);

app.post('/api/articles',
  authenticate,
  hasPermission('article', 'create'),
  createArticle
);

app.delete('/api/articles/:id',
  authenticate,
  hasPermission('article', 'delete'),
  deleteArticle
);
```

### 2.3 Schéma de base de données RBAC

```sql
-- Tables pour RBAC en PostgreSQL
CREATE TABLE roles (
  id SERIAL PRIMARY KEY,
  name VARCHAR(50) UNIQUE NOT NULL,
  parent_role_id INTEGER REFERENCES roles(id)
);

CREATE TABLE permissions (
  id SERIAL PRIMARY KEY,
  resource VARCHAR(100) NOT NULL,
  action VARCHAR(50) NOT NULL,
  UNIQUE(resource, action)
);

CREATE TABLE role_permissions (
  role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
  permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, role_id)
);

-- Requête récursive pour résoudre les permissions héritées
WITH RECURSIVE role_hierarchy AS (
  SELECT id, name, parent_role_id FROM roles WHERE name = 'editor'
  UNION ALL
  SELECT r.id, r.name, r.parent_role_id
  FROM roles r
  JOIN role_hierarchy rh ON r.id = rh.parent_role_id
)
SELECT DISTINCT p.resource, p.action
FROM role_hierarchy rh
JOIN role_permissions rp ON rh.id = rp.role_id
JOIN permissions p ON rp.permission_id = p.id;
```

---

## 3. ABAC — Attribute-Based Access Control

### 3.1 Concepts

ABAC prend des décisions basées sur des **attributs** :
- **Sujet** (qui) : rôle, département, ancienneté, localisation
- **Ressource** (quoi) : propriétaire, classification, date de création
- **Action** (comment) : read, write, delete, approve
- **Environnement** (contexte) : heure, IP, appareil

### 3.2 Comparaison RBAC vs ABAC

| Critère | RBAC | ABAC |
|---|---|---|
| Complexité | Simple | Complexe |
| Granularité | Par rôle | Par attribut |
| Flexibilité | Limitée | Très élevée |
| Maintenance | Rôles à gérer | Politiques à gérer |
| Performance | Rapide (lookup simple) | Variable (évaluation de règles) |
| Use case | Apps simples/moyennes | Systèmes complexes, conformité |

### 3.3 Implémentation ABAC

```typescript
// Définition d'une politique ABAC
interface ABACPolicy {
  name: string;
  description: string;
  effect: 'allow' | 'deny';
  conditions: {
    subject?: Record<string, unknown>;
    resource?: Record<string, unknown>;
    action?: string[];
    environment?: Record<string, unknown>;
  };
}

const policies: ABACPolicy[] = [
  {
    name: 'author-can-edit-own-articles',
    description: "Un auteur peut modifier ses propres articles",
    effect: 'allow',
    conditions: {
      action: ['update'],
      resource: { type: 'article' },
      // Le subject.id doit correspondre au resource.authorId
    },
  },
  {
    name: 'no-access-outside-business-hours',
    description: "Pas d'accès aux données sensibles hors heures ouvrées",
    effect: 'deny',
    conditions: {
      resource: { classification: 'confidential' },
      environment: { outsideBusinessHours: true },
    },
  },
];

// Moteur d'évaluation ABAC
interface ABACContext {
  subject: { id: string; role: string; department: string; [key: string]: unknown };
  resource: { type: string; ownerId?: string; classification?: string; [key: string]: unknown };
  action: string;
  environment: { time: Date; ip: string; [key: string]: unknown };
}

function evaluateABAC(context: ABACContext): boolean {
  // Deny par défaut
  let allowed = false;

  for (const policy of policies) {
    const matches = matchesPolicy(context, policy);
    if (matches && policy.effect === 'deny') return false;
    if (matches && policy.effect === 'allow') allowed = true;
  }

  return allowed;
}

// Middleware ABAC pour Express
function abacMiddleware(resourceType: string, action: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const resource = await loadResource(resourceType, req.params.id);
    const now = new Date();

    const context: ABACContext = {
      subject: {
        id: req.user.id,
        role: req.user.role,
        department: req.user.department,
      },
      resource: {
        type: resourceType,
        ownerId: resource.authorId,
        classification: resource.classification,
      },
      action,
      environment: {
        time: now,
        ip: req.ip,
        outsideBusinessHours: now.getHours() < 8 || now.getHours() > 18,
      },
    };

    if (!evaluateABAC(context)) {
      return res.status(403).json({ error: 'Accès refusé par la politique ABAC' });
    }

    next();
  };
}
```

---

## 4. ACL — Access Control Lists

### 4.1 Concept

Une ACL associe directement des **sujets** à des **ressources** avec des **permissions** spécifiques.

```typescript
// Modèle ACL pour un système de fichiers/documents
interface ACLEntry {
  resourceId: string;
  subjectId: string;
  subjectType: 'user' | 'group';
  permissions: ('read' | 'write' | 'delete' | 'share')[];
}

// Table en base de données
// ┌────────────┬───────────┬─────────────┬───────────┐
// │ resource_id│ subject_id│ subject_type│ permission│
// ├────────────┼───────────┼─────────────┼───────────┤
// │ doc-123    │ user-1    │ user        │ read      │
// │ doc-123    │ user-1    │ user        │ write     │
// │ doc-123    │ group-dev │ group       │ read      │
// │ doc-456    │ user-2    │ user        │ read      │
// └────────────┴───────────┴─────────────┴───────────┘
```

### 4.2 Row-Level Security en PostgreSQL

PostgreSQL dispose d'un mécanisme natif de RLS qui filtre les lignes au niveau de la base de données.

```sql
-- Activer RLS sur une table
ALTER TABLE articles ENABLE ROW LEVEL SECURITY;

-- Politique : les utilisateurs ne voient que leurs propres articles
CREATE POLICY user_articles_select ON articles
  FOR SELECT
  USING (author_id = current_setting('app.current_user_id')::INTEGER);

-- Politique : les utilisateurs ne modifient que leurs articles
CREATE POLICY user_articles_update ON articles
  FOR UPDATE
  USING (author_id = current_setting('app.current_user_id')::INTEGER);

-- Politique : les admins voient tout
CREATE POLICY admin_articles_all ON articles
  FOR ALL
  USING (current_setting('app.current_user_role') = 'admin');

-- Politique de publication : les articles publiés sont visibles par tous
CREATE POLICY published_articles ON articles
  FOR SELECT
  USING (status = 'published');
```

```typescript
// Utilisation dans Node.js — définir le contexte utilisateur
async function queryWithRLS<T>(
  userId: string,
  userRole: string,
  query: string,
  params: unknown[]
): Promise<T[]> {
  const client = await pool.connect();
  try {
    // Définir le contexte utilisateur pour les politiques RLS
    await client.query("SET LOCAL app.current_user_id = $1", [userId]);
    await client.query("SET LOCAL app.current_user_role = $1", [userRole]);

    const result = await client.query(query, params);
    return result.rows;
  } finally {
    client.release();
  }
}

// Les requêtes seront automatiquement filtrées par RLS
app.get('/api/articles', authenticate, async (req, res) => {
  const articles = await queryWithRLS(
    req.user.id,
    req.user.role,
    'SELECT * FROM articles ORDER BY created_at DESC',
    []
  );
  res.json(articles);
});
```

---

## 5. Broken Access Control — OWASP A01

### 5.1 IDOR (Insecure Direct Object Reference)

L'utilisateur manipule un identifiant pour accéder aux données d'un autre.

```typescript
// ❌ VULNÉRABLE : aucune vérification de propriété
app.get('/api/invoices/:id', authenticate, async (req, res) => {
  const invoice = await db.query(
    'SELECT * FROM invoices WHERE id = $1',
    [req.params.id]  // L'user-1 peut voir l'invoice de user-2
  );
  res.json(invoice.rows[0]);
});

// ✅ SÉCURISÉ : vérifier que la facture appartient à l'utilisateur
app.get('/api/invoices/:id', authenticate, async (req, res) => {
  const invoice = await db.query(
    'SELECT * FROM invoices WHERE id = $1 AND user_id = $2',
    [req.params.id, req.user.id]
  );
  if (!invoice.rows[0]) {
    return res.status(404).json({ error: 'Facture non trouvée' });
  }
  res.json(invoice.rows[0]);
});
```

### 5.2 Privilege Escalation

#### Escalation horizontale

Un utilisateur accède aux données d'un **autre utilisateur** de même niveau.

```typescript
// ❌ L'utilisateur peut changer le userId dans la requête
app.put('/api/profile', authenticate, async (req, res) => {
  const { userId, name, email } = req.body;
  await updateUser(userId, { name, email }); // userId non vérifié !
});

// ✅ Utiliser exclusivement l'ID du token
app.put('/api/profile', authenticate, async (req, res) => {
  const { name, email } = req.body;
  await updateUser(req.user.id, { name, email }); // ID du token authentifié
});
```

#### Escalation verticale

Un utilisateur standard accède aux fonctions **admin**.

```typescript
// ❌ Vérification uniquement côté frontend
// Le bouton "Admin" est masqué, mais l'endpoint n'est pas protégé
app.delete('/api/users/:id', authenticate, async (req, res) => {
  await deleteUser(req.params.id); // Pas de vérification du rôle !
});

// ✅ Vérification côté serveur OBLIGATOIRE
app.delete('/api/users/:id',
  authenticate,
  authorize('admin'),
  async (req, res) => {
    await deleteUser(req.params.id);
    res.json({ message: 'Utilisateur supprimé' });
  }
);
```

### 5.3 Missing Function-Level Access Control

```typescript
// ❌ L'endpoint admin n'a pas de protection
app.get('/api/admin/stats', async (req, res) => {
  const stats = await getSystemStats();
  res.json(stats);
});

// ❌ L'API de debug est exposée en production
app.get('/api/debug/config', (req, res) => {
  res.json(process.env); // Fuite de TOUS les secrets !
});

// ✅ Protection systématique + pas de routes sensibles en production
if (process.env.NODE_ENV !== 'production') {
  app.get('/api/debug/config', authenticate, authorize('admin'), (req, res) => {
    res.json({ nodeEnv: process.env.NODE_ENV });
  });
}
```

---

## 6. Implémentation NestJS Guards

### 6.1 Guard d'authentification

```typescript
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = request.headers.authorization?.replace('Bearer ', '');

    if (!token) return false;

    try {
      const payload = await this.jwtService.verifyAsync(token);
      request.user = payload;
      return true;
    } catch {
      return false;
    }
  }
}
```

### 6.2 Guard RBAC avec décorateur

```typescript
import { SetMetadata } from '@nestjs/common';

// Décorateur personnalisé pour définir les rôles requis
export const Roles = (...roles: string[]) => SetMetadata('roles', roles);

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>('roles', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) return true; // Pas de rôle requis

    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.includes(user.role);
  }
}

// Utilisation dans un contrôleur
@Controller('articles')
@UseGuards(AuthGuard, RolesGuard)
export class ArticlesController {
  @Get()
  @Roles('viewer', 'editor', 'admin')
  findAll() { /* ... */ }

  @Post()
  @Roles('editor', 'admin')
  create(@Body() dto: CreateArticleDto) { /* ... */ }

  @Delete(':id')
  @Roles('admin')
  remove(@Param('id') id: string) { /* ... */ }
}
```

### 6.3 CASL.js — Abilities

CASL est une bibliothèque isomorphe pour la gestion de permissions.

```typescript
import { AbilityBuilder, createMongoAbility, MongoAbility } from '@casl/ability';

type Actions = 'create' | 'read' | 'update' | 'delete' | 'manage';
type Subjects = 'Article' | 'Comment' | 'User' | 'all';

type AppAbility = MongoAbility<[Actions, Subjects]>;

function defineAbilityFor(user: { id: string; role: string }): AppAbility {
  const { can, cannot, build } = new AbilityBuilder<AppAbility>(createMongoAbility);

  switch (user.role) {
    case 'admin':
      can('manage', 'all'); // Peut tout faire
      break;

    case 'editor':
      can('read', 'Article');
      can('create', 'Article');
      can('update', 'Article', { authorId: user.id }); // Ses propres articles
      can('read', 'Comment');
      can('create', 'Comment');
      can('delete', 'Comment', { authorId: user.id });
      break;

    case 'viewer':
      can('read', 'Article');
      can('read', 'Comment');
      can('create', 'Comment');
      break;

    default:
      // Utilisateur non reconnu → aucune permission
      break;
  }

  return build();
}

// Utilisation
const ability = defineAbilityFor({ id: 'user-123', role: 'editor' });

ability.can('read', 'Article');                           // true
ability.can('delete', 'Article');                          // false
ability.can('update', subject('Article', { authorId: 'user-123' })); // true
ability.can('update', subject('Article', { authorId: 'other-user' })); // false
```

---

## 7. API Gateway et autorisation centralisée

### Architecture avec Gateway

```
Client → API Gateway → Microservice A
                    → Microservice B
                    → Microservice C

L'API Gateway centralise :
- Authentification (vérification du JWT)
- Rate limiting
- Autorisation de premier niveau (rôle)
- Le microservice gère l'autorisation fine (ownership, ABAC)
```

```typescript
// Nginx / Kong / AWS API Gateway configuration concept
const gatewayConfig = {
  routes: [
    {
      path: '/api/admin/*',
      upstream: 'admin-service',
      plugins: {
        auth: { required: true },
        acl: { allowedGroups: ['admin'] },
        rateLimit: { requests: 100, per: 'minute' },
      },
    },
    {
      path: '/api/public/*',
      upstream: 'public-service',
      plugins: {
        auth: { required: false },
        rateLimit: { requests: 1000, per: 'minute' },
      },
    },
  ],
};
```

---

## 8. Récapitulatif

### Quel modèle choisir ?

| Situation | Modèle recommandé |
|---|---|
| Application simple avec quelques rôles | RBAC |
| Règles dépendant du propriétaire de la ressource | RBAC + ownership check |
| Règles complexes multi-critères | ABAC |
| Système de fichiers / documents partagés | ACL |
| Protection au niveau BDD | PostgreSQL RLS |

### Checklist d'autorisation

1. **Deny by default** — refuser tout accès non explicitement autorisé
2. **Vérification côté serveur** — ne jamais se fier au frontend
3. **Vérifier la propriété** — toujours filtrer par user ID
4. **Tester les cas limites** — IDOR, escalation horizontale et verticale
5. **Logger les accès refusés** — détection d'attaques
6. **Review régulière** — audit des rôles et permissions

---

> **Prochain module** : Cryptographie — chiffrement, hashing et gestion des secrets.
