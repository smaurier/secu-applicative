---
titre: Injection — comprendre pour prévenir (SQLi, XSS, command injection)
cours: 14-securite-applicative
notions:
  - séparation données / instructions
  - SQL injection
  - "requêtes paramétrées ($1 / ?)"
  - protection via ORM
  - "raw queries non protégées"
  - "XSS stored / reflected / DOM"
  - échappement contextuel de sortie
  - "auto-escaping des frameworks (React / Vue / Angular)"
  - "sanitization HTML (DOMPurify)"
  - "CSP en défense en profondeur"
  - command injection
  - "execFile vs exec"
  - validation d'entrée en allow-list
outcomes:
  - sait expliquer le mécanisme commun à toutes les injections (données interprétées comme instructions)
  - sait réécrire une requête SQL concaténée en requête paramétrée
  - sait choisir la défense XSS correcte selon le contexte de sortie
  - sait remplacer exec par execFile pour neutraliser la command injection
  - sait ordonner les défenses (paramétrage/échappement d'abord, CSP et validation en renfort)
prerequis:
  - module 00 introduction-securite (modèle de menace, defense in depth)
  - module 01 owasp-top10 (catégorie A03 Injection)
next: 03-authentification
libs: []
tribuzen: back-office TribuZen — API famille (recherche de membres, commentaires du journal, upload de justificatifs) où transitent des données d'enfants
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

<!-- Angle DÉFENSIF strict. Les extraits vulnérables ne sont montrés que pour
     être CORRIGÉS. Aucun payload d'attaque prêt à l'emploi contre un tiers :
     on illustre le mécanisme sur du code que TU possèdes, pour le durcir. -->

# Injection — comprendre le mécanisme pour le prévenir

> **Outcomes — tu sauras FAIRE :** réécrire une requête concaténée en requête paramétrée, choisir la défense XSS selon le contexte de sortie, neutraliser une command injection avec `execFile`, ordonner les couches de défense.
> **Difficulté :** :star::star::star:
>
> **Portée :** ce module couvre les trois familles d'injection les plus fréquentes en full-stack JS/TS — **SQLi**, **XSS** (stored / reflected / DOM), **command injection** — sous l'angle **défensif**. On montre du code vulnérable **uniquement pour le corriger**. Les headers de sécurité (CSP en détail) sont approfondis au **module 06** ; l'authentification au **module 03**. NoSQL et path traversal sont évoqués en pièges mais traités ailleurs.

## 1. Cas concret d'abord

Tu reprends l'API back-office de TribuZen. Un endpoint permet aux parents de chercher un membre de leur famille par prénom. Un collègue a écrit ceci :

```typescript
// GET /api/family/:familyId/members?q=alice
// ❌ Code à AUDITER — ne pas déployer
import { Pool } from 'pg'
const pool = new Pool()

app.get('/api/family/:familyId/members', async (req, res) => {
  const { q } = req.query
  // La valeur de q est collée directement dans le texte SQL
  const sql = `SELECT id, first_name FROM members WHERE first_name LIKE '%${q}%'`
  const result = await pool.query(sql)
  res.json(result.rows)
})
```

Trois questions à te poser avant de merger :

1. **Que devient la requête si `q` contient une apostrophe ?** La chaîne SQL est cassée : le texte fourni sort de la zone « donnée » et devient de la « structure » de requête. C'est **exactement** la faille SQLi — la frontière entre données et instructions n'existe plus.
2. **Le même prénom est ensuite affiché dans le journal familial en HTML.** S'il contient `<` et `>`, le navigateur peut l'interpréter comme des balises au lieu du texte. C'est le mécanisme XSS.
3. **Où est la donnée sensible ?** Ici, des prénoms d'**enfants**. Une injection qui fait fuiter ou modifier ces lignes est un incident RGPD, pas juste un bug.

Ce module te donne les réflexes pour transformer ce code en version sûre : **requête paramétrée** côté base, **échappement contextuel** côté affichage. On corrige `members` en §3.

---

## 2. Théorie complète, concise

### 2.1 Le mécanisme unique derrière toutes les injections

Une **injection** survient quand une donnée non fiable est envoyée à un interpréteur (moteur SQL, moteur HTML du navigateur, shell système) et que cet interpréteur ne distingue plus **ce qui est de la donnée** de **ce qui est une instruction**.

```
donnée non fiable  →  concaténée dans une commande  →  interpréteur exécute le tout
```

La défense fondamentale est toujours la même idée : **garder la séparation données / instructions**. Les techniques concrètes changent selon l'interpréteur (paramétrage pour SQL, encodage pour HTML, tableau d'arguments pour le shell), mais le principe est constant. Retiens ça : tu ne « nettoies » pas une injection, tu **empêches le mélange**.

### 2.2 SQL injection — le paramétrage résout le problème à la racine

Le problème vient de la **construction de la requête par concaténation de texte**. La solution n'est pas de filtrer les apostrophes : c'est de ne jamais mettre la donnée dans le texte SQL. Une **requête paramétrée** (prepared statement) envoie au moteur d'abord la structure avec des emplacements (`$1`, `?`), puis les valeurs à part. Le moteur les traite comme des données pures, jamais comme du SQL.

```typescript
// ✅ pg (PostgreSQL) — placeholders $1, $2...
const result = await pool.query(
  'SELECT id, first_name FROM members WHERE first_name = $1',
  [q], // la valeur voyage séparée de la structure : jamais interprétée comme SQL
)

// ✅ mysql2 — placeholders ?
const [rows] = await connection.execute(
  'SELECT id, first_name FROM members WHERE first_name = ?',
  [q],
)
```

D'après l'**OWASP SQL Injection Prevention Cheat Sheet**, les défenses primaires, dans l'ordre :

1. **Prepared statements / requêtes paramétrées** — le premier choix recommandé.
2. **Procédures stockées** — équivalent si elles n'assemblent pas de SQL dynamique en interne.
3. **Validation d'entrée en allow-list** — pour les fragments qui ne peuvent **pas** être des paramètres (nom de table, de colonne, sens de tri).
4. **Échappement manuel** — **fortement déconseillé** par l'OWASP : fragile, ne garantit pas la protection dans tous les cas.

Défenses **additionnelles** : **moindre privilège** du compte base (l'API ne doit pas être `superuser`) et validation en allow-list en renfort.

Un **ORM** (Prisma, TypeORM) paramétrise pour toi tant que tu passes par son API :

```typescript
// ✅ Prisma paramétrise automatiquement
const members = await prisma.member.findMany({
  where: { firstName: q },
  select: { id: true, firstName: true },
})

// ⚠️ MAIS : une raw query concaténée redevient vulnérable
// ❌ NE PAS faire — la protection de l'ORM ne s'applique plus
await prisma.$queryRawUnsafe(`SELECT * FROM members WHERE first_name = '${q}'`)

// ✅ raw query avec paramètres (tagged template = paramétré)
await prisma.$queryRaw`SELECT * FROM members WHERE first_name = ${q}`
```

Règle : **l'ORM protège l'API typée ; les échappatoires « raw » ne sont paramétrés que si tu passes les valeurs à part.**

### 2.3 XSS — l'échappement de sortie, contextuel

Le **XSS (Cross-Site Scripting)** injecte du code interprété par le navigateur d'une **autre** victime. Trois variantes selon *où* la donnée transite :

| Type | Chemin de la donnée | Exemple TribuZen |
|---|---|---|
| **Reflected** | requête → renvoyée immédiatement dans la réponse | terme de recherche affiché sur la page de résultats |
| **Stored** | requête → base → affichée plus tard à tous | commentaire du journal familial |
| **DOM-based** | manipulée côté client sans passer par le serveur | valeur d'URL injectée via `innerHTML` |

La défense centrale est l'**encodage de sortie contextuel** : encoder la donnée selon l'endroit exact où elle est insérée. L'**OWASP XSS Prevention Cheat Sheet** classe les contextes :

- **Corps HTML** → entités HTML (`<` → `&lt;`, `&` → `&amp;`).
- **Attribut HTML** → encodage d'attribut agressif, et **toujours guillemeter** l'attribut.
- **JavaScript** → encodage `\uXXXX`, uniquement dans une valeur de chaîne guillemetée.
- **URL** → percent-encoding.
- **CSS** → uniquement en valeur de propriété, encodage hex CSS.

Concrètement, tu délègues cet encodage plutôt que de le faire à la main :

```typescript
// ❌ VULNÉRABLE — donnée collée dans du HTML sans encodage (reflected XSS)
app.get('/search', (req, res) => {
  res.send(`<h1>Résultats pour : ${req.query.q}</h1>`)
})

// ✅ Défense 1 — un moteur de template à auto-escaping (les {{ }} sont encodés)
// eta / nunjucks / etc. encodent les variables du contexte automatiquement
app.get('/search', (req, res) => {
  res.render('search', { q: req.query.q }) // le template affiche {{ q }} encodé
})
```

> Note SSR : dans un template à auto-escaping, une variable affichée via la syntaxe moustache est encodée **à condition** de rester une variable du contexte. Ne jamais construire le texte du template avec la donnée (voir piège SSTI en §4).

### 2.4 XSS — les frameworks front encodent par défaut

React, Vue et Angular **encodent le contenu textuel par défaut**. Le XSS front vient presque toujours d'un **échappatoire** volontaire. L'OWASP est explicite : la première ligne de défense est le framework, et il faut **éviter** ses `dangerouslySetInnerHTML` / `v-html` / `bypassSecurityTrustHtml`.

```tsx
// ✅ React encode automatiquement
function Comment({ text }: { text: string }) {
  return <p>{text}</p> // sûr : le texte est encodé
}

// ❌ échappatoire — n'utiliser QUE sur du HTML déjà sanitizé
// return <p dangerouslySetInnerHTML={{ __html: text }} />
```

```vue
<!-- ✅ interpolation Vue : encodée -->
<template>
  <p>{{ text }}</p>
</template>

<!-- ❌ v-html : n'utiliser QUE sur du HTML déjà sanitizé -->
<!-- <p v-html="text"></p> -->
```

Quand l'utilisateur doit **légitimement** produire du HTML riche (éditeur WYSIWYG du journal familial), on **sanitize** avec **DOMPurify** avant l'affichage :

```typescript
import DOMPurify from 'isomorphic-dompurify'

// ✅ retire balises et attributs dangereux, garde le HTML de mise en forme
const clean = DOMPurify.sanitize(richText, {
  ALLOWED_TAGS: ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'li'],
  ALLOWED_ATTR: ['href'],
})
```

### 2.5 Command injection — séparer le binaire de ses arguments

Quand du code passe une chaîne à un **shell**, les métacaractères (`;`, `|`, `&&`, backtick) sont interprétés comme des séparateurs de commandes. La défense : **ne pas passer par un shell** et fournir les arguments dans un **tableau**, via `execFile` (ou `spawn` sans `shell: true`).

```typescript
import { exec, execFile } from 'node:child_process'

// ❌ VULNÉRABLE — exec lance un shell qui interprète ; | &&
exec(`ping -c 4 ${host}`, cb)

// ✅ execFile — le binaire reçoit un tableau d'arguments, pas de shell
// même si host contient des métacaractères, ils restent un argument littéral
execFile('ping', ['-c', '4', host], cb)
```

| Fonction | Shell ? | Sûr par défaut ? |
|---|---|---|
| `exec()` | oui | ❌ interprète `;`, `\|`, `&&` |
| `execFile()` | non | ✅ arguments passés en tableau |
| `spawn()` | non (sauf `shell: true`) | ✅ sauf si `shell: true` |

En renfort, une **validation allow-list** de l'entrée (ex. un hostname doit matcher un motif strict) réduit encore la surface.

### 2.6 L'ordre des couches de défense

Les défenses se cumulent, mais elles ne sont **pas interchangeables**. L'OWASP insiste : la validation d'entrée et la CSP sont des **renforts**, pas la protection principale.

```
1. PARAMÉTRAGE / ENCODAGE  ← la vraie barrière (SQL paramétré, sortie encodée, execFile)
2. VALIDATION D'ENTRÉE     ← réduit la surface (allow-list, types, longueurs) — jamais suffisante seule
3. CSP / moindre privilège ← défense en profondeur, limite l'impact si une couche cède
```

**Content-Security-Policy** (détaillée au module 06) est une couche « en profondeur » : elle limite l'exécution de scripts injectés **même si** un XSS passe, mais l'OWASP avertit explicitement qu'elle ne remplace **pas** l'encodage contextuel.

---

## 3. Worked examples

### Exemple 1 — durcir l'endpoint de recherche de membres (SQLi)

On corrige le code du §1, étape par étape.

```typescript
// GET /api/family/:familyId/members?q=alice — VERSION SÛRE
import { Pool } from 'pg'
import { z } from 'zod'

const pool = new Pool()

// (2) validation d'entrée en renfort : q est une string bornée
const QuerySchema = z.object({
  q: z.string().min(1).max(50),
})

app.get('/api/family/:familyId/members', async (req, res) => {
  const parsed = QuerySchema.safeParse(req.query)
  if (!parsed.success) {
    return res.status(400).json({ error: 'Paramètre de recherche invalide' })
  }
  const { q } = parsed.data

  // (1) LA barrière : requête paramétrée.
  //     Le motif LIKE est construit côté JS, puis passé comme VALEUR ($1).
  //     La structure SQL ne contient jamais la donnée utilisateur.
  const result = await pool.query(
    `SELECT id, first_name
       FROM members
      WHERE family_id = $1
        AND first_name ILIKE $2`,
    [req.params.familyId, `%${q}%`],
  )

  // (3) moindre privilège : on ne SELECT que les colonnes nécessaires,
  //     pas SELECT * (évite d'exposer des colonnes sensibles par accident)
  res.json(result.rows)
})
```

Ce qui a changé et **pourquoi c'est correct** :
- La donnée `q` voyage dans le tableau `[...]`, jamais dans le texte SQL → l'apostrophe redevient un simple caractère, plus un séparateur de requête.
- Le `%...%` du `LIKE` est assemblé **avant** le passage en paramètre : c'est la valeur qui contient les `%`, pas la structure.
- La validation Zod (couche 2) rejette les entrées absurdes tôt, mais ce n'est **pas** elle qui empêche l'injection — c'est le paramétrage.

### Exemple 2 — afficher un commentaire de journal sans stored XSS

Un parent poste un commentaire dans le journal familial ; il est stocké puis affiché à toute la famille. Deux cas : texte simple vs HTML riche.

```typescript
// --- Écriture : on stocke le texte BRUT (l'encodage se fait à l'affichage) ---
app.post('/api/journal/:id/comments', async (req, res) => {
  const { content } = req.body
  // stockage paramétré (pas de SQLi non plus)
  await pool.query(
    'INSERT INTO comments (journal_id, content) VALUES ($1, $2)',
    [req.params.id, content],
  )
  res.status(201).json({ ok: true })
})
```

```tsx
// --- Lecture, cas A : commentaire = texte simple (le cas courant) ---
// ✅ React encode : n'importe quel < > devient du texte, pas une balise
function CommentText({ content }: { content: string }) {
  return <p className="comment">{content}</p>
}

// --- Lecture, cas B : commentaire = HTML riche autorisé (gras, liens) ---
import DOMPurify from 'isomorphic-dompurify'

function RichComment({ content }: { content: string }) {
  // On sanitize AVANT de passer à l'échappatoire.
  // Sans DOMPurify ici, ce serait une stored XSS servie à toute la famille.
  const clean = DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'br'],
    ALLOWED_ATTR: ['href'],
  })
  return <p className="comment" dangerouslySetInnerHTML={{ __html: clean }} />
}
```

**Pourquoi c'est correct :**
- Cas A : on ne fait **rien de spécial** — l'encodage par défaut de React suffit. C'est le choix par défaut à privilégier.
- Cas B : on n'ouvre l'échappatoire `dangerouslySetInnerHTML` **qu'après** DOMPurify, avec une allow-list de balises. Le HTML dangereux (`<script>`, gestionnaires `on*`) est retiré avant l'affichage.
- En **renfort** (couche 3), une CSP `script-src 'self'` limiterait l'exécution d'un éventuel script qui passerait — mais elle ne remplace pas la sanitization.

---

## 4. Pièges & misconceptions

### PIÈGE #1 — « Je filtre les apostrophes, donc je suis protégé contre la SQLi »

Le blocage/échappement manuel de caractères est **fragile** (l'OWASP le classe « fortement déconseillé ») : encodages alternatifs, champs numériques, noms de colonnes… il y a toujours un contournement. **Le correct :** requête paramétrée. Tu ne filtres pas la donnée, tu l'empêches d'atteindre l'interpréteur en tant que code.

### PIÈGE #2 — « Mon ORM me protège, donc tout est sûr »

Vrai pour l'API typée de l'ORM. **Faux** dès que tu utilises une **raw query** en concaténant (`$queryRawUnsafe`, `dataSource.query(\`...${x}...\`)`). L'échappatoire raw court-circuite la protection. **Le correct :** passer les valeurs comme paramètres même en raw (`$queryRaw` tagged template, ou `query(sql, [params])`).

### PIÈGE #3 — « La validation d'entrée (Zod) suffit contre l'injection »

La validation **réduit la surface** mais ne remplace pas le paramétrage/encodage. Une string parfaitement valide (`O'Brien`) casse une requête concaténée. **Le correct :** validation **en plus** de la vraie barrière, jamais à sa place. C'est une couche 2, pas la couche 1.

### PIÈGE #4 — « Encoder une fois suffit, quel que soit l'endroit »

L'encodage est **contextuel**. Une donnée sûre dans un corps HTML peut être dangereuse dans un attribut, une URL, ou du JavaScript inline. Encoder pour le mauvais contexte laisse la faille ouverte. **Le correct :** encoder selon le contexte de sortie (corps HTML / attribut / JS / URL / CSS) — ce que font les frameworks et moteurs de template quand tu passes par eux.

### PIÈGE #5 — command injection : `execFile('sh', ['-c', cmd])` n'est pas plus sûr

Passer par `execFile` **mais** en invoquant un shell (`sh -c "..."`, ou `spawn(..., { shell: true })`) réintroduit exactement la faille. **Le correct :** `execFile(binaire, [args])` où le binaire est fixe et les args forment un tableau — jamais un shell qui ré-interprète la chaîne.

### PIÈGE #6 — SSTI : mettre la donnée dans le *code* du template, pas dans le *contexte*

Construire le template lui-même avec l'entrée (`renderString('<h1>' + name + '</h1>')`) transforme l'auto-escaping en Server-Side Template Injection : la donnée est évaluée comme expression de template. **Le correct :** la donnée est toujours une **variable du contexte** (`render('page', { name })`), jamais du texte de template. (Path traversal et NoSQL injection suivent la même logique « données ≠ instructions » — traités dans les modules dédiés.)

---

## 5. Ancrage TribuZen

TribuZen manipule des données d'**enfants** : une injection y est un incident RGPD, pas un simple bug. Les points d'entrée à durcir en priorité :

**API famille (`src/server/routes/family.ts`)** — recherche de membres (Exemple 1). Toutes les requêtes passent par des **prepared statements** via le client `pg` ou Prisma. Aucune concaténation SQL, aucune raw query non paramétrée. Compte base applicatif en **moindre privilège** (pas de `DROP`, pas d'accès aux tables d'audit).

**Journal familial (`src/components/journal/`)** — commentaires (Exemple 2). Texte simple → encodage par défaut React/Vue. HTML riche → **DOMPurify** avec allow-list de balises avant tout `dangerouslySetInnerHTML` / `v-html`.

**Upload de justificatifs (`src/server/routes/uploads.ts`)** — le nom de fichier fourni n'est **jamais** utilisé tel quel comme chemin (path traversal) ni passé à un shell (aucun `exec` sur des noms de fichiers ; conversion/scan via un binaire appelé en `execFile` avec arguments en tableau).

**En renfort transversal** — CSP `script-src 'self'` (module 06) sur tout le front, cookies `HttpOnly` pour que le cookie de session ne soit pas lisible par un script même en cas de XSS résiduel.

```
tribuzen/
  src/
    server/
      routes/
        family.ts      ← requêtes paramétrées (pg / Prisma)
        uploads.ts     ← noms de fichiers validés, jamais dans un shell
    components/
      journal/
        RichComment.tsx ← DOMPurify avant dangerouslySetInnerHTML
```

---

## 6. Points clés

1. Toutes les injections partagent un mécanisme : une donnée devient une instruction faute de séparation. La défense = **rétablir la séparation**.
2. **SQLi** → requêtes paramétrées (`$1`, `?`) ou ORM. Jamais de concaténation, même « juste pour un prénom ».
3. Un **ORM** protège son API typée ; les **raw queries** doivent quand même passer les valeurs en paramètres.
4. **XSS** → encodage de **sortie contextuel** ; les frameworks front encodent par défaut, le danger vient des échappatoires (`dangerouslySetInnerHTML`, `v-html`).
5. HTML riche légitime → **DOMPurify** (allow-list) avant l'affichage.
6. **Command injection** → `execFile`/`spawn` sans shell, arguments en **tableau** ; `exec` interprète les métacaractères.
7. **Validation d'entrée** et **CSP** sont des **renforts** (défense en profondeur), jamais la barrière principale.
8. Ordre des couches : paramétrage/encodage d'abord, validation ensuite, CSP + moindre privilège pour limiter l'impact.

---

## 7. Seeds Anki

```
Quel est le mécanisme commun à toutes les injections ?|Une donnée non fiable atteint un interpréteur (SQL, HTML, shell) qui ne distingue plus les données des instructions. Défense = rétablir la séparation données/instructions.
Quelle est la défense primaire n°1 de l'OWASP contre la SQL injection ?|Les requêtes paramétrées (prepared statements) : la structure SQL est envoyée avec des placeholders ($1, ?), les valeurs voyagent à part et ne sont jamais interprétées comme du SQL.
Pourquoi filtrer/échapper les apostrophes ne suffit pas contre la SQLi ?|L'OWASP classe l'échappement manuel comme fortement déconseillé : fragile, contournable (encodages alternatifs, contextes numériques). La vraie barrière est le paramétrage.
Un ORM protège-t-il contre toute SQLi ?|Non : seulement son API typée. Une raw query concaténée ($queryRawUnsafe, dataSource.query avec template literal) redevient vulnérable. Passer les valeurs en paramètres même en raw.
Quelles sont les trois variantes de XSS et leur chemin ?|Reflected (requête renvoyée immédiatement), Stored (stockée en base puis servie à tous), DOM-based (manipulée côté client sans passer par le serveur).
Quelle est la défense centrale contre le XSS selon l'OWASP ?|L'encodage de sortie contextuel (corps HTML, attribut, JS, URL, CSS), assuré par défaut par les frameworks. Éviter les échappatoires (dangerouslySetInnerHTML, v-html, bypassSecurityTrust).
Quand et comment autoriser du HTML riche utilisateur sans XSS ?|Sanitizer avec DOMPurify et une allow-list de balises/attributs AVANT de l'injecter via dangerouslySetInnerHTML / v-html.
Comment neutraliser une command injection en Node ?|Utiliser execFile (ou spawn sans shell:true) avec les arguments dans un tableau, au lieu de exec qui lance un shell interprétant ; | &&. Le binaire reste fixe.
Où se situe la CSP dans l'ordre des défenses anti-XSS ?|En défense en profondeur (couche 3) : elle limite l'exécution d'un script injecté si une couche cède, mais l'OWASP avertit qu'elle ne remplace pas l'encodage contextuel.
```

---

## Pont vers le lab

> Lab associé : `labs/lab-02-injection/README.md`. **Audit défensif** : on te fournit un fichier de routes API volontairement vulnérable (SQLi + stored XSS + command injection) ; tu le réécris en version sûre (paramétré, encodé, `execFile`) et tu justifies chaque correction. Zéro harnais auto-correcteur — le coach valide la revue en session.
