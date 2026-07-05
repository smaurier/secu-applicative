---
titre: Autorisation — contrôle d'accès, RBAC/ABAC, IDOR/BOLA, moindre privilège
cours: 14-securite-applicative
notions: ["authZ vs authN", "deny by default", "moindre privilège", "RBAC", "ABAC / ReBAC", "contrôle d'accès au niveau objet", "IDOR (Insecure Direct Object Reference)", "BOLA (API1:2023)", "escalade horizontale / verticale", "contrôle côté serveur (jamais client)", "centraliser la logique d'autorisation", "requêtes scellées par propriétaire"]
outcomes:
  - "sait distinguer authentification (401) et autorisation (403) et poser le contrôle d'accès au bon endroit"
  - "sait choisir entre RBAC, ABAC et ReBAC selon la granularité voulue et modéliser un rôle parent/admin"
  - "sait détecter et corriger un IDOR/BOLA en scellant la requête par le propriétaire tiré de la session"
  - "sait appliquer deny by default, le moindre privilège et centraliser la décision d'accès côté serveur"
  - "sait qu'un contrôle d'accès purement côté client (bouton masqué) n'est pas une protection"
prerequis:
  - "Introduction sécurité — modèle de menace, CIA, defense in depth (module 00)"
  - "OWASP Top 10 2021 — A01 Broken Access Control (module 01)"
  - "Authentification — sessions, identité de l'utilisateur (module 03)"
  - "OIDC/PKCE et WebAuthn — l'identité prouvée en amont (modules 03b, 03c)"
next: 05-cryptographie
libs: []
tribuzen: "back-office TribuZen — autorisation : un parent ne voit et ne modifie que SA famille (contrôle au niveau objet), rôles parent/admin, deny by default"
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Autorisation — contrôle d'accès, RBAC/ABAC, IDOR/BOLA, moindre privilège

> **Outcomes — tu sauras FAIRE :** séparer authN et authZ, choisir un modèle (RBAC/ABAC/ReBAC), détecter et corriger un IDOR/BOLA en scellant la requête par le propriétaire, appliquer deny by default + moindre privilège, et poser le contrôle **côté serveur** — jamais dans le bouton masqué du front.
> **Difficulté :** :star::star::star:
>
> **Angle : DÉFENSIF.** On montre les failles pour les **comprendre et les corriger** dans TON code, jamais pour attaquer un tiers.
>
> **Portée :** ce module répond à « **qu'as-tu le droit de faire ?** ». L'identité (« qui es-tu ? ») est déjà prouvée par les modules 03 (mot de passe/session), 03b (OIDC/PKCE) et 03c (WebAuthn/passkeys). Ici on suppose l'utilisateur **authentifié** et on décide ce qu'il peut lire/écrire. Le **Broken Access Control** est la catégorie **A01 du Top 10 2021** — la plus répandue.

## 1. Cas concret d'abord

Dans TribuZen, chaque parent gère les activités de **ses** enfants — des **données de mineurs**, l'enjeu le plus sensible de l'app. Un collègue a livré ce endpoint pour afficher une fiche famille. Il « marche » : le parent connecté voit bien sa famille.

```typescript
// GET /api/families/:id — AVANT durcissement. NE PAS copier en prod.
app.get('/api/families/:id', authenticate, async (req, res) => {
  // authenticate a déjà posé req.user (identité prouvée, module 03)
  const family = await db.family.findUnique({
    where: { id: req.params.id }, // (!) on fait confiance à l'ID de l'URL
  })
  if (!family) return res.status(404).json({ error: 'Famille introuvable' })
  res.json(family) // renvoyée sans vérifier À QUI elle appartient
})
```

Le parent `alice` est authentifié et ouvre `/api/families/f-alice` : correct. Mais rien ne l'empêche de changer l'URL en `/api/families/f-bob` et de lire la famille de quelqu'un d'autre — enfants, adresses, plannings compris. L'ID est un **identifiant d'objet direct** exposé, et le serveur ne vérifie **jamais** que l'objet demandé appartient à l'appelant.

C'est un **IDOR** (Insecure Direct Object Reference) — au niveau API, OWASP l'appelle **BOLA** (Broken Object Level Authorization, `API1:2023`), *la* faille d'API la plus fréquente. OWASP : le serveur « s'appuie sur des paramètres comme les ID d'objet envoyés par le client pour décider quels objets accéder », sans valider les droits.

**Le trou :** l'utilisateur est bien **authentifié**, mais il n'est pas **autorisé** sur *cet objet précis*. `authenticate` répond « qui es-tu ? » ; personne ne répond « as-tu le droit de voir CETTE famille ? ».

À la fin du module, ce endpoint **scelle** la requête par le propriétaire tiré de la session, refuse par défaut, renvoie `404` (pas `403`, pour ne pas confirmer l'existence de l'objet), et le rôle `admin` est vérifié **côté serveur**. C'est le fil rouge du lab.

---

## 2. Théorie complète, concise

### 2.1 authN ≠ authZ (le cadrage qui évite la moitié des failles)

- **Authentification (authN)** — « qui es-tu ? ». Modules 03/03b/03c. Échec → **401 Unauthorized**.
- **Autorisation (authZ)** — « qu'as-tu le droit de faire ? ». Ce module. Échec → **403 Forbidden**.

Être authentifié ne dit **rien** sur les droits. La faille du §1 vient précisément de croire que « connecté » = « autorisé ». Toujours enchaîner les deux : d'abord prouver l'identité, ensuite décider l'accès.

> Nuance HTTP : sur un objet **dont on ne veut pas révéler l'existence** à un tiers (une famille qui n'est pas la sienne), on répond souvent **404** plutôt que 403 — un 403 confirmerait « cet objet existe, mais pas pour toi » (fuite d'information). Le 403 reste correct quand l'existence n'est pas un secret.

### 2.2 Les deux dimensions à contrôler

Le contrôle d'accès se décline sur deux axes — OWASP recommande d'appliquer le moindre privilège sur **les deux** :

- **Function-level (vertical)** — « ce **type d'action** t'est-il permis ? ». Un parent peut-il appeler `DELETE /api/users/:id` (fonction admin) ? Failles : *escalade verticale*, *Missing Function-Level Access Control* (au niveau API : **BFLA**).
- **Object-level (horizontal)** — « cet **objet précis** t'appartient-il ? ». Alice peut-elle lire la famille de Bob (même niveau de privilège) ? Failles : *escalade horizontale*, **IDOR / BOLA**.

Les deux sont indépendants : protéger l'un ne protège pas l'autre. Un endpoint peut être réservé aux parents (function-level OK) tout en laissant un parent lire la famille d'un autre (object-level KO).

### 2.3 Les principes non négociables (OWASP Authorization Cheat Sheet)

Vérifiés sur `cheatsheetseries.owasp.org` (Authorization Cheat Sheet, 2026-07) :

1. **Deny by default** — « l'application doit toujours prendre une décision, implicite ou explicite, de refuser ou permettre ». En pratique : on part de « refusé » et on **ajoute** des autorisations ; jamais l'inverse. Une route sans règle explicite = accès refusé, pas ouvert.
2. **Moindre privilège** — accorder le **minimum** nécessaire, horizontalement et verticalement. Un parent n'a aucun droit sur les autres familles ; un compte de service n'a que ses tables.
3. **Valider à chaque requête** — « la permission doit être validée à chaque requête, quelle qu'en soit la source (AJAX, serveur…) ». Pas de « vérifié au login, on fait confiance ensuite ».
4. **Contrôle côté serveur uniquement** — « les contrôles doivent être faits côté serveur, à la gateway, ou dans une fonction serverless ». Jamais côté client.
5. **Centraliser la logique** — utiliser des filtres/middlewares/guards à l'échelle du framework plutôt qu'un `if` recopié dans chaque handler (source d'oublis). « Centraliser la logique de gestion des échecs d'accès. »
6. **Échouer proprement + logger** — refuser sans fuiter d'info de debug, et **journaliser les accès refusés** (détection d'attaque). Tester la logique d'autorisation (tests unitaires + intégration).

### 2.4 RBAC — Role-Based Access Control

Les permissions sont attribuées à des **rôles**, et l'utilisateur hérite des permissions **via** son/ses rôle(s).

- **Rôle** : ensemble nommé de permissions (`parent`, `admin`, `support`).
- **Permission** : droit d'une action sur un type de ressource (`family:read`, `activity:delete`).
- **Hiérarchie** (optionnelle) : un rôle peut hériter d'un autre (`admin` hérite de `parent`).

```typescript
type Action = 'read' | 'create' | 'update' | 'delete'
type Resource = 'family' | 'activity' | 'user'

// deny by default : une (rôle, ressource) absente = aucune permission
const rolePermissions: Record<string, `${Resource}:${Action}`[]> = {
  parent: ['family:read', 'family:update', 'activity:create', 'activity:delete'],
  admin: ['user:read', 'user:delete', 'family:read'], // + tout ce qu'on lui ajoute
}

function roleCan(role: string, resource: Resource, action: Action): boolean {
  return rolePermissions[role]?.includes(`${resource}:${action}`) ?? false // défaut: false
}
```

RBAC répond bien au **function-level** (« un parent peut-il supprimer une activité ? »). Il ne répond **pas** au **object-level** : « `parent` peut lire *une* famille » ne dit pas *laquelle*. D'où la limite qui suit.

### 2.5 ABAC / ReBAC — quand le rôle ne suffit plus

OWASP note que les modèles à attributs/relations offrent une logique plus fine, souvent mieux adaptée que le rôle seul aux apps modernes.

- **ABAC (Attribute-Based)** — la décision dépend d'**attributs** : sujet (rôle, service), ressource (**propriétaire**, classification), action, environnement (heure, IP). C'est ABAC qui exprime « un parent peut lire une famille **dont il est le propriétaire** » : `resource.ownerId === subject.id`.
- **ReBAC (Relationship-Based)** — la décision dépend d'une **relation** dans un graphe (« Alice est *parent-de* Léo », « Léo est *membre-de* la famille F »). C'est le modèle de Google Zanzibar ; adapté au partage fin (co-parent invité sur une famille).

Règle pratique : **RBAC pour le grossier (le type d'action), ABAC/ReBAC pour le fin (quel objet)**. TribuZen combine les deux : RBAC pour `parent` vs `admin`, ABAC (ownership) pour « SA famille ».

### 2.6 Contrôle au niveau objet : IDOR / BOLA et sa parade

**IDOR** (Insecure Direct Object Reference) : l'utilisateur manipule un identifiant (URL, body, param) pour atteindre un objet qui n'est pas le sien, faute de **contrôle d'accès au niveau objet**. Trois ingrédients (OWASP) : (1) un objet accessible, (2) une référence (ID/UUID), (3) **l'absence de validation d'autorisation sur cet objet**.

**La parade la plus robuste : sceller la requête par le propriétaire**, tiré de la **session/token** (jamais du body). On ne charge jamais « l'objet `:id` » puis on vérifie ; on charge « l'objet `:id` **ET** appartenant à `req.user.id` » en une seule requête scellée.

```typescript
// ❌ VULNÉRABLE — IDOR : lookup non scellé, puis (au mieux) check oublié
const family = await db.family.findUnique({ where: { id: req.params.id } })

// ✅ SÛR — requête scellée par le propriétaire venu de la SESSION, pas de l'URL
const family = await db.family.findFirst({
  where: { id: req.params.id, ownerId: req.user.id }, // deny by default naturel
})
// family === null => 404 : indistinguable de "n'existe pas" => pas de fuite d'existence
```

OWASP (IDOR Prevention Cheat Sheet) : « Vérifier la permission de l'utilisateur à **chaque** tentative d'accès » et **restreindre les lookups au jeu de données accessible** à l'utilisateur. Défense en profondeur complémentaire (**pas** une protection à elle seule) : utiliser des **UUID/valeurs aléatoires** comme clés plutôt que des entiers séquentiels devinables.

**PostgreSQL Row-Level Security (RLS)** pousse ce filtrage dans la base : une `POLICY` filtre les lignes selon un contexte (`current_setting('app.current_user_id')`). C'est un excellent **filet de sécurité** en profondeur — mais il **complète** le contrôle applicatif, il ne le remplace pas (et suppose de propager le bon contexte utilisateur par requête).

### 2.7 Où poser le contrôle — jamais dans le client

Un contrôle côté client (masquer un bouton, cacher une route Vue, filtrer un menu) est de l'**UX**, pas de la sécurité : le navigateur est sous le contrôle de l'utilisateur, qui peut appeler l'API directement (curl, Postman, DevTools). OWASP : contrôles **server-side, à la gateway, ou en serverless** — point.

Répartition typique (déférée à l'archi → cours 13 / infra → cours 12) :

- **Gateway / edge** : authZ de premier niveau (rôle, appartenance à un groupe). Grossier.
- **Service applicatif** : authZ **fine** — ownership, ABAC, règles métier. C'est ici que vit « SA famille ».
- **Base (RLS)** : filet de dernier recours en profondeur.

Le front peut **aussi** masquer le bouton admin — pour l'UX — mais l'endpoint reste protégé **indépendamment**.

---

## 3. Worked examples

### Exemple 1 — Corriger l'IDOR du §1 (object-level, ABAC ownership)

On reprend `GET /api/families/:id` et on scelle la requête.

```typescript
// GET /api/families/:id — APRÈS durcissement
app.get('/api/families/:id', authenticate, async (req, res) => {
  // Le propriétaire vient de la SESSION (req.user), JAMAIS du body/URL.
  // Requête scellée : id demandé ET ownerId = utilisateur courant.
  const family = await db.family.findFirst({
    where: { id: req.params.id, ownerId: req.user.id },
  })

  // Un admin, lui, a le droit transverse (function-level) — vérifié côté serveur.
  if (!family && req.user.role === 'admin') {
    const asAdmin = await db.family.findUnique({ where: { id: req.params.id } })
    if (asAdmin) return res.json(asAdmin)
  }

  // Deny by default : rien trouvé pour cet utilisateur => 404 (pas 403).
  // 404 ne confirme pas l'existence de l'objet à un tiers => pas de fuite.
  if (!family) return res.status(404).json({ error: 'Famille introuvable' })

  res.json(family)
})
```

Ce qui a changé : le propriétaire est tiré de la session, la requête est scellée (impossible de lire la famille d'autrui), le droit `admin` est un contrôle **serveur** explicite, et le refus est un `404` sobre.

### Exemple 2 — Guards NestJS : function-level (RBAC) + object-level (ownership)

En NestJS, on **centralise** l'autorisation dans des guards réutilisables plutôt que dans chaque méthode.

```typescript
// rôles requis, posés par décorateur — function-level (vertical)
import { SetMetadata } from '@nestjs/common'
export const Roles = (...roles: string[]) => SetMetadata('roles', roles)

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}
  canActivate(ctx: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<string[]>('roles', [
      ctx.getHandler(),
      ctx.getClass(),
    ])
    if (!required) return false // DENY BY DEFAULT : pas de @Roles => refusé
    const { user } = ctx.switchToHttp().getRequest()
    return required.includes(user.role)
  }
}

@Controller('families')
@UseGuards(AuthGuard, RolesGuard) // authN puis authZ, dans cet ordre
export class FamiliesController {
  constructor(private families: FamiliesService) {}

  // function-level : réservé aux parents et admins
  @Get(':id')
  @Roles('parent', 'admin')
  async findOne(@Param('id') id: string, @Req() req) {
    // object-level : la couche service scelle par propriétaire (ownership)
    // -> le RBAC ne suffit PAS, on ajoute le contrôle d'objet ici.
    return this.families.findOwnedOrAdmin(id, req.user)
  }

  // function-level : réservé aux admins (escalade verticale bloquée)
  @Delete('users/:id')
  @Roles('admin')
  removeUser(@Param('id') id: string) {
    return this.families.deleteUser(id)
  }
}
```

```typescript
// FamiliesService — object-level centralisé (une seule source de vérité)
async findOwnedOrAdmin(id: string, user: { id: string; role: string }) {
  const where =
    user.role === 'admin'
      ? { id } // admin : accès transverse assumé (moindre privilège quand même : lecture)
      : { id, ownerId: user.id } // parent : scellé par propriétaire
  const family = await this.db.family.findFirst({ where })
  if (!family) throw new NotFoundException() // deny by default => 404
  return family
}
```

Les deux dimensions sont couvertes : le **guard** filtre le type d'action (RBAC), le **service** filtre l'objet (ownership), et la règle d'objet est écrite **une fois**.

---

## 4. Pièges & misconceptions

### PIÈGE #1 — « L'utilisateur est authentifié, donc il est autorisé »
Faux, et c'est la faille du §1. authN (401) répond « qui es-tu ? » ; authZ (403) répond « as-tu le droit ? ». Un parent connecté n'a **aucun** droit sur la famille d'un autre. Correct : après `authenticate`, décider l'accès **sur l'objet précis**.

### PIÈGE #2 — Vérifier le rôle mais pas la propriété (RBAC sans object-level)
`@Roles('parent')` protège le *type d'action* mais laisse `parent` A lire la famille de `parent` B : c'est un **IDOR/BOLA**. RBAC ≠ contrôle d'objet. Correct : ajouter le scellement par propriétaire (`ownerId = req.user.id`) en plus du rôle.

### PIÈGE #3 — Faire confiance à l'ID/owner venu du client
`updateFamily(req.body.ownerId, ...)` ou `where: { id: req.params.id }` seul : l'attaquant fournit l'ID qu'il veut. Correct : l'identité du propriétaire vient **toujours** de la session/token (`req.user.id`), jamais du body ni de l'URL.

### PIÈGE #4 — Contrôle d'accès côté client
Masquer le bouton « Supprimer » ou cacher la route admin dans Vue n'est **pas** une protection : l'API est appelable directement (curl/Postman). Correct : le contrôle vit **côté serveur** ; le masquage front est un bonus UX, jamais la barrière.

### PIÈGE #5 — Allow by default (ouvrir puis restreindre)
Une route sans règle, un `switch(role)` sans `default`, un nouveau endpoint oublié : s'il est ouvert par défaut, chaque oubli est une faille. Correct : **deny by default** — refuser tant qu'une règle n'autorise pas explicitement (`default: return false`, guard qui refuse sans `@Roles`).

### PIÈGE #6 — Répondre 403 là où 404 protégerait mieux
Sur un objet dont l'existence est sensible, `403` confirme « cet objet existe, mais pas pour toi » → fuite exploitable pour cartographier les IDs. Correct : sur les objets privés, répondre **404** (indistinguable de « n'existe pas »). Le 403 reste OK quand l'existence n'est pas secrète (ex. zone admin connue).

### PIÈGE #7 — Croire que des UUID « aléatoires » suffisent
Remplacer `id: 42` par un UUID rend l'ID difficile à deviner, mais **ne remplace pas** le contrôle d'accès : l'UUID fuit dans les logs, les partages, le cache. OWASP le classe en défense **en profondeur**, pas en protection. Correct : sceller la requête par propriétaire ; l'UUID est un plus.

### PIÈGE #8 — Copier le `if (user.role === ...)` dans chaque handler
La logique dispersée finit par diverger (un endpoint oublié, une règle obsolète). OWASP recommande de **centraliser** (guard/middleware/policy). Correct : une source de vérité (guard RBAC + service ownership), testée unitairement.

---

## 5. Ancrage TribuZen

L'autorisation est ce qui garantit la promesse centrale de TribuZen : **un parent ne voit et ne modifie que SA famille** — des données de mineurs, donc le contrôle d'accès n'est pas optionnel.

Où ça vit dans `smaurier/tribuzen` (back-office NestJS) :

```
tribuzen-api/
  src/
    auth/
      roles.guard.ts          ← RBAC function-level (parent / admin), deny by default
      roles.decorator.ts      ← @Roles(...) posé sur les routes
    families/
      families.controller.ts  ← @Roles + @UseGuards, ordre authN→authZ
      families.service.ts      ← object-level : findOwnedOrAdmin (scellé par ownerId)
    activities/
      activities.service.ts    ← scellé via la famille propriétaire (ReBAC : activité→famille→parent)
    common/
      access-denied.filter.ts  ← échec propre + log des refus (détection d'attaque)
```

Points d'ancrage concrets :
- **Object-level (le cœur)** : toute lecture/écriture de `family`/`activity` est **scellée par `ownerId` = parent de la session**. Un IDOR sur `/families/:id` est fermé par la requête scellée.
- **Function-level** : `parent` vs `admin` via `RolesGuard` ; suppression d'utilisateur réservée à `admin` (escalade verticale bloquée côté serveur).
- **Co-parent (ReBAC)** : un second parent invité sur une famille est autorisé **par la relation** parent↔famille, pas par un rôle global.
- **Filet en profondeur** : PostgreSQL RLS sur `families`/`activities` en complément (jamais à la place) du contrôle applicatif.
- **Front Vue** : masque les actions admin pour l'UX — mais l'API refuse **indépendamment**.

L'identité (« qui est ce parent ? ») vient des modules 03/03b/03c ; ce module 04 décide « quelle famille a-t-il le droit de toucher ? ».

---

## 6. Points clés

1. **authN (401) ≠ authZ (403)** : authentifié ne veut pas dire autorisé. Enchaîner identité puis droits, à **chaque requête**.
2. Deux dimensions indépendantes : **function-level** (type d'action, escalade verticale, BFLA) et **object-level** (objet précis, escalade horizontale, **IDOR/BOLA**). Couvrir les deux.
3. **RBAC** pour le grossier (rôle → permissions) ; **ABAC/ReBAC** pour le fin (propriétaire/relation → *quel* objet). TribuZen combine les deux.
4. **IDOR/BOLA** (A01 / API1:2023) = pas de contrôle au niveau objet. Parade robuste : **sceller la requête par le propriétaire tiré de la session** (`id ET ownerId = req.user.id`), pas du body.
5. **Deny by default** + **moindre privilège** : partir de « refusé », n'ajouter que le minimum, `default: false` partout.
6. Contrôle **côté serveur uniquement** (gateway/service/RLS) ; le masquage côté client est de l'UX, pas de la sécurité.
7. **Centraliser** la décision (guards/middlewares/policies), **logger les refus**, **tester** l'autorisation. UUID = défense en profondeur, jamais la protection.
8. Sur objet privé, préférer **404 à 403** pour ne pas confirmer l'existence.

---

## 7. Seeds Anki

```
Différence entre authentification et autorisation (codes HTTP) ?|authN = "qui es-tu ?" (échec 401), prouvée par login/OIDC/WebAuthn. authZ = "qu'as-tu le droit de faire ?" (échec 403), décide l'accès. Authentifié ne veut PAS dire autorisé.
Qu'est-ce qu'un IDOR / BOLA et sa parade principale ?|Accès à un objet d'autrui en manipulant un identifiant (URL/body), faute de contrôle au niveau objet. A01 (2021) / API1:2023. Parade : sceller la requête par le propriétaire tiré de la SESSION (WHERE id ET ownerId = req.user.id), jamais l'ID du body.
Function-level vs object-level access control ?|Function-level (vertical) = "ce TYPE d'action t'est-il permis ?" (escalade verticale, BFLA), géré par RBAC. Object-level (horizontal) = "cet OBJET précis t'appartient-il ?" (escalade horizontale, IDOR/BOLA), géré par ownership/ABAC. Indépendants : couvrir les deux.
Pourquoi RBAC ne suffit-il pas à empêcher un IDOR ?|RBAC dit "un parent peut lire UNE famille", pas LAQUELLE. Il protège le type d'action, pas l'objet. Il faut ajouter un contrôle object-level : ownerId = utilisateur courant (ABAC/ReBAC).
Que signifie "deny by default" en autorisation ?|Partir de "refusé" et n'AJOUTER que les autorisations explicites (default: return false, guard qui refuse sans @Roles). Chaque route/rôle oublié reste fermé, pas ouvert. Couplé au moindre privilège.
Pourquoi un contrôle d'accès côté client n'est-il pas une protection ?|Le navigateur est sous le contrôle de l'utilisateur : il peut appeler l'API directement (curl/Postman/DevTools). Masquer un bouton = UX. OWASP : contrôles server-side / gateway / serverless uniquement. Le front masque en plus, l'API refuse indépendamment.
Des UUID aléatoires suffisent-ils à corriger un IDOR ?|Non. Un UUID rend l'ID dur à deviner mais fuit (logs, partages, cache) et ne vérifie AUCUN droit. OWASP : défense en profondeur, jamais la protection. La protection = sceller la requête par propriétaire.
Sur un objet privé, faut-il répondre 403 ou 404 à un accès non autorisé ?|Souvent 404 : un 403 confirme "cet objet existe mais pas pour toi" (fuite d'existence, cartographie d'IDs). 404 est indistinguable de "n'existe pas". Le 403 reste OK quand l'existence n'est pas secrète.
Où placer le contrôle d'autorisation dans une architecture ?|Gateway = authZ grossière (rôle/groupe). Service applicatif = authZ fine (ownership, ABAC, métier). Base = RLS en filet de profondeur (complète, ne remplace pas). Centraliser via guards/middlewares, jamais un if recopié par handler.
```

---

## Pont vers le lab

> Lab associé : `labs/lab-04-autorisation/README.md`. Exercice **défensif** : auditer et durcir le contrôle d'accès d'une API TribuZen — corriger un IDOR en scellant la requête par le propriétaire, ajouter le contrôle function-level (RBAC parent/admin) côté serveur, appliquer deny by default. Vrai outil, pas de harnais simulé. Corrigé commenté + variante J+30.
