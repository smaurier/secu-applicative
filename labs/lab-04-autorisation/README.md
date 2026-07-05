<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Lab 04 — Autorisation : durcir le contrôle d'accès d'une API TribuZen

> **Outcome :** à la fin, tu sais **auditer** une API TribuZen, **repérer un IDOR/BOLA** et le **corriger** en scellant la requête par le propriétaire, ajouter un contrôle de rôle **côté serveur** (RBAC parent/admin), et appliquer **deny by default** — le tout sur du vrai code exécutable.
> **Vrai outil :** TypeScript + Express + Prisma (ou un stub `db` typé), exécuté avec `tsx`. Aucun harnais auto-correcteur.
> **Feedback :** le coach valide en session (revue de code + scénarios d'accès croisés). Pas de test-runner qui coche des cases à ta place.
>
> **Angle : DÉFENSIF.** Objectif = **fermer** des failles dans TON API, pas attaquer un système tiers. On simule deux parents et un admin dans TON propre code pour prouver que le durcissement tient.

---

## Énoncé

Tu reprends le back-office TribuZen. On te livre trois endpoints qui « marchent » en démo mais qui laissent un parent atteindre les données d'une **autre** famille (données de mineurs). Ta mission : **auditer, corriger, prouver**.

L'API vulnérable de départ (à copier dans `authz-api.ts`) :

```typescript
// authz-api.ts — API TribuZen AVANT durcissement. NE PAS livrer en l'état.
import express, { type Request, type Response, type NextFunction } from 'express'

// --- Stub de données (remplace Prisma pour le lab ; même forme d'API) ---
type Family = { id: string; ownerId: string; label: string; children: string[] }
type User = { id: string; role: 'parent' | 'admin' }

const families: Family[] = [
  { id: 'f-alice', ownerId: 'u-alice', label: 'Famille Alice', children: ['Léo', 'Mia'] },
  { id: 'f-bob', ownerId: 'u-bob', label: 'Famille Bob', children: ['Noé'] },
]

const db = {
  family: {
    // Volontairement "brut" : lookup par id seul (c'est le piège à corriger).
    findUnique: async ({ where }: { where: { id: string } }) =>
      families.find((f) => f.id === where.id) ?? null,
    // findFirst accepte un where partiel { id?, ownerId? } — À TOI de t'en servir.
    findFirst: async ({ where }: { where: Partial<Pick<Family, 'id' | 'ownerId'>> }) =>
      families.find(
        (f) =>
          (where.id === undefined || f.id === where.id) &&
          (where.ownerId === undefined || f.ownerId === where.ownerId),
      ) ?? null,
    delete: async ({ where }: { where: { id: string } }) => {
      const i = families.findIndex((f) => f.id === where.id)
      if (i >= 0) families.splice(i, 1)
    },
  },
}

// --- Faux "authenticate" : pose req.user depuis un header (module 03 déjà fait) ---
// En prod ce serait la session/JWT vérifié. Ici on lit un header pour SIMULER
// différents utilisateurs authentifiés dans TON propre code.
declare global {
  namespace Express {
    interface Request {
      user?: User
    }
  }
}
const USERS: Record<string, User> = {
  'u-alice': { id: 'u-alice', role: 'parent' },
  'u-bob': { id: 'u-bob', role: 'parent' },
  'u-root': { id: 'u-root', role: 'admin' },
}
function authenticate(req: Request, res: Response, next: NextFunction) {
  const uid = req.header('x-user-id') ?? ''
  const user = USERS[uid]
  if (!user) return res.status(401).json({ error: 'Non authentifié' })
  req.user = user
  next()
}

const app = express()
app.use(express.json())

// ❌ (1) IDOR : lookup par id seul, aucune vérification de propriété
app.get('/api/families/:id', authenticate, async (req, res) => {
  const family = await db.family.findUnique({ where: { id: req.params.id } })
  if (!family) return res.status(404).json({ error: 'Famille introuvable' })
  res.json(family)
})

// ❌ (2) Escalade horizontale : ownerId pris dans le body (fourni par le client)
app.put('/api/families/:id', authenticate, async (req, res) => {
  const target = await db.family.findFirst({ where: { ownerId: req.body.ownerId } })
  if (!target) return res.status(404).json({ error: 'Famille introuvable' })
  res.json({ ok: true, updated: target.id })
})

// ❌ (3) Escalade verticale : aucun contrôle de rôle sur une action admin
app.delete('/api/users/:id', authenticate, async (req, res) => {
  // n'importe quel parent peut supprimer n'importe quel utilisateur
  res.json({ ok: true, deleted: req.params.id })
})

app.listen(3000, () => console.log('API sur http://localhost:3000'))
```

**Pas de gap-fill.** Tu écris la version durcie complète à partir de ce starter.

### Cahier des charges du durcissement

1. `GET /api/families/:id` — un `parent` ne doit lire **que sa propre** famille. Un `admin` peut lire n'importe laquelle. Un parent qui demande la famille d'un autre reçoit **404** (pas 403 : ne pas confirmer l'existence).
2. `PUT /api/families/:id` — le propriétaire visé vient **de la session** (`req.user.id`), **jamais** du body. Impossible de cibler la famille d'autrui via `ownerId`.
3. `DELETE /api/users/:id` — réservé au rôle `admin`, vérifié **côté serveur**. Un `parent` reçoit **403**.
4. **Deny by default** : centralise le contrôle de rôle dans un middleware `requireRole(...)` qui **refuse** si le rôle n'est pas explicitement listé.
5. **Prouve-le** : écris un petit scénario (`scenario.ts` ou en bas du fichier) qui, via `fetch`/`supertest` ou de simples appels, montre que :
   - `u-alice` lit `f-alice` ✅ mais pas `f-bob` (404) ✅
   - `u-bob` ne peut pas modifier `f-alice` ✅
   - `u-alice` (parent) reçoit 403 sur `DELETE /api/users/...` ✅
   - `u-root` (admin) lit `f-bob` ✅ et peut supprimer ✅

### Lancement

```bash
npm init -y
npm pkg set type=module          # ESM : requis pour le top-level await du scénario de test
npm i express
npm i -D tsx @types/express
npx tsx authz-api.ts
# puis, dans un autre terminal, joue le scénario d'accès croisés
```

---

## Étapes (en friction)

1. **Audit d'abord (à l'écrit).** Pour chacun des 3 endpoints, note : est-ce du function-level ou de l'object-level ? Quel est le trou ? Quelle dimension (verticale/horizontale) est cassée ? Ne code rien encore.
2. **Corrige l'IDOR (1)** — remplace `findUnique({ id })` par une requête **scellée** `findFirst({ id, ownerId: req.user.id })`. Ajoute la branche `admin` (lecture transverse). Refus = `404`.
3. **Ferme l'escalade horizontale (2)** — ignore `req.body.ownerId` ; le propriétaire = `req.user.id`. Vérifie la propriété **avant** toute écriture.
4. **Écris `requireRole(...roles)`** — un middleware qui lit `req.user.role`, **refuse (403) par défaut** si le rôle n'est pas dans la liste. Applique-le à `DELETE /api/users/:id` avec `requireRole('admin')`.
5. **Centralise** — vérifie que la logique de rôle n'est écrite **qu'une fois** (dans `requireRole`), pas recopiée dans chaque handler.
6. **Prouve** — écris le scénario d'accès croisés (étape 5 du cahier des charges) et fais-le tourner. Chaque ligne doit afficher le code HTTP attendu.
7. **Cas limites** — que se passe-t-il si `x-user-id` est absent (401, pas 403) ? Si un parent vise une famille **inexistante** (404, même réponse que « pas la tienne » → pas de fuite) ?

---

## Corrigé complet commenté

```typescript
// authz-api.ts — APRÈS durcissement (partie serveur ; stub db/authenticate inchangés)
import express, { type Request, type Response, type NextFunction } from 'express'

// ... (families, db, authenticate, USERS : identiques au starter) ...

const app = express()
app.use(express.json())

// ── Contrôle function-level CENTRALISÉ : deny by default ──────────────────
// Une seule source de vérité pour "ce type d'action est-il permis à ce rôle ?".
function requireRole(...allowed: Array<User['role']>) {
  return (req: Request, res: Response, next: NextFunction) => {
    // authenticate a déjà garanti req.user (sinon 401 plus haut).
    // Deny by default : si le rôle n'est PAS explicitement listé -> 403.
    if (!req.user || !allowed.includes(req.user.role)) {
      // On logge le refus (détection d'abus) sans fuiter d'info au client.
      console.warn(`[authz] refus ${req.user?.id ?? '?'} sur ${req.method} ${req.path}`)
      return res.status(403).json({ error: 'Accès refusé' })
    }
    next()
  }
}

// ── (1) IDOR corrigé : requête SCELLÉE par le propriétaire de la session ───
app.get('/api/families/:id', authenticate, requireRole('parent', 'admin'), async (req, res) => {
  const me = req.user!

  // Object-level : le parent ne peut charger QUE sa famille.
  // ownerId vient de la SESSION (me.id), jamais de l'URL/body.
  const scoped =
    me.role === 'admin'
      ? { id: req.params.id } // admin : lecture transverse assumée
      : { id: req.params.id, ownerId: me.id } // parent : scellé

  const family = await db.family.findFirst({ where: scoped })

  // Deny by default -> 404 (et pas 403) : un parent qui vise la famille d'un
  // autre reçoit la MÊME réponse que si elle n'existait pas => pas de fuite d'existence.
  if (!family) return res.status(404).json({ error: 'Famille introuvable' })

  res.json(family)
})

// ── (2) Escalade horizontale fermée : propriétaire = session, pas le body ──
app.put('/api/families/:id', authenticate, requireRole('parent', 'admin'), async (req, res) => {
  const me = req.user!

  // On IGNORE volontairement req.body.ownerId. La cible autorisée est
  // déterminée par l'identité de session + l'id de l'URL, scellés ensemble.
  const scoped =
    me.role === 'admin' ? { id: req.params.id } : { id: req.params.id, ownerId: me.id }

  const target = await db.family.findFirst({ where: scoped })
  if (!target) return res.status(404).json({ error: 'Famille introuvable' })

  // ... application des champs autorisés (label, etc.) — jamais ownerId depuis le client ...
  res.json({ ok: true, updated: target.id })
})

// ── (3) Escalade verticale bloquée : action admin vérifiée CÔTÉ SERVEUR ────
app.delete(
  '/api/users/:id',
  authenticate,
  requireRole('admin'), // un parent -> 403, décidé par le serveur (pas un bouton masqué)
  async (req, res) => {
    res.json({ ok: true, deleted: req.params.id })
  },
)

app.listen(3000, () => console.log('API durcie sur http://localhost:3000'))
```

```typescript
// scenario.ts — preuve d'accès croisés (à lancer API démarrée)
const base = 'http://localhost:3000'
const as = (uid: string) => ({ headers: { 'x-user-id': uid, 'content-type': 'application/json' } })

async function check(label: string, res: Response, expected: number) {
  const ok = res.status === expected ? 'OK ' : 'KO '
  console.log(`${ok}[${res.status} attendu ${expected}] ${label}`)
}

// Alice lit SA famille -> 200 ; la famille de Bob -> 404 (pas de fuite)
await check('alice -> f-alice', await fetch(`${base}/api/families/f-alice`, as('u-alice')), 200)
await check('alice -> f-bob (IDOR fermé)', await fetch(`${base}/api/families/f-bob`, as('u-alice')), 404)

// Bob ne peut pas modifier la famille d'Alice (ownerId du body ignoré)
await check(
  'bob -> PUT f-alice',
  await fetch(`${base}/api/families/f-alice`, {
    method: 'PUT',
    ...as('u-bob'),
    body: JSON.stringify({ ownerId: 'u-alice', label: 'hijack' }),
  }),
  404,
)

// Un parent ne peut pas supprimer un utilisateur -> 403 (escalade verticale bloquée)
await check(
  'alice -> DELETE user',
  await fetch(`${base}/api/users/u-bob`, { method: 'DELETE', ...as('u-alice') }),
  403,
)

// L'admin, lui, a l'accès transverse
await check('root(admin) -> f-bob', await fetch(`${base}/api/families/f-bob`, as('u-root')), 200)
await check(
  'root(admin) -> DELETE user',
  await fetch(`${base}/api/users/u-bob`, { method: 'DELETE', ...as('u-root') }),
  200,
)

// Cas limite : pas d'identité -> 401 (authN), surtout PAS 403
await check('anonyme -> f-alice', await fetch(`${base}/api/families/f-alice`), 401)
```

**Pourquoi ce corrigé est correct :**
- **IDOR fermé** : la requête est **scellée** (`id` ET `ownerId = req.user.id`) — le parent ne *peut pas* charger la famille d'un autre, même en devinant l'ID. Le propriétaire vient de la session, jamais du client.
- **Escalade horizontale fermée** : `req.body.ownerId` est ignoré ; on ne cible que ce que la session autorise.
- **Escalade verticale bloquée** : `requireRole('admin')` décide **côté serveur** ; masquer le bouton front n'aurait rien protégé.
- **Deny by default + centralisation** : `requireRole` refuse par défaut et concentre la règle de rôle en un seul endroit — pas de `if (role)` recopié, pas d'endpoint oublié ouvert.
- **Pas de fuite d'existence** : parent visant une famille d'autrui = **404**, identique à « n'existe pas ». Absence d'identité = **401**, jamais 403.

---

## Variante J+30 (fading)

**Même objectif, contraintes ajoutées :**

Reprends l'API **de mémoire, en 30 minutes**, sans rouvrir ce corrigé ni le module 04, avec les ajouts suivants :

1. **ReBAC léger — le co-parent.** Ajoute une table `familyMembers: { familyId, userId }[]`. Un utilisateur peut lire/modifier une famille s'il en est le propriétaire **OU** un membre invité (relation), pas seulement le propriétaire. Le contrôle object-level devient « la relation existe-t-elle ? ».
2. **Filtrage de champs selon le rôle.** `GET /api/families/:id` ne renvoie la liste `children` (données de mineurs) qu'aux membres de la famille ; pour un `admin` en lecture transverse, masque `children` par défaut (moindre privilège : l'admin gère, il n'a pas à voir les prénoms des enfants).
3. **Log structuré des refus** : chaque 403/404-pour-cause-d'accès émet une ligne `{ userId, action, resourceId, decision }`.

**Critère de réussite :** un co-parent invité lit bien la famille partagée ; un parent non-membre reçoit 404 ; l'admin voit la famille mais **pas** `children`. Le scénario d'accès croisés le prouve.

---

## Application TribuZen

Dans le repo `smaurier/tribuzen` (back-office NestJS), ce contrôle vit ici :

```
tribuzen-api/
  src/
    auth/
      roles.guard.ts          ← équivalent NestJS de requireRole (deny by default)
      roles.decorator.ts      ← @Roles('parent', 'admin')
    families/
      families.controller.ts  ← @UseGuards(AuthGuard, RolesGuard) + @Roles
      families.service.ts      ← findOwnedOrAdmin : requête scellée par ownerId
    common/
      access-denied.filter.ts  ← 404/403 propre + log des refus
```

**Différences par rapport au lab :**
- Le contrôle de rôle est un **guard NestJS** (`RolesGuard` + `@Roles`) au lieu d'un middleware Express — même principe (deny by default, centralisé).
- `db` est **Prisma** réel (`prisma.family.findFirst({ where: { id, ownerId } })`) — la requête scellée est identique.
- `authenticate` est la vraie session/JWT du module 03, pas un header `x-user-id`.
- PostgreSQL **RLS** est ajouté en filet de profondeur sur `families`/`activities` (complète le contrôle applicatif, ne le remplace pas).

**Commit cible :**
```
fix(authz): scelle l'accès famille par propriétaire (IDOR fermé) + RolesGuard deny-by-default
```
