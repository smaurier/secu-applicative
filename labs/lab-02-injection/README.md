<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

<!-- Lab DÉFENSIF : auditer un code vulnérable QUE TU POSSÈDES et le réécrire
     en version sûre. Aucun exercice d'attaque contre un système tiers. -->

# Lab 02 — Injection : auditer et durcir une API vulnérable

> **Outcome :** à la fin, tu sais repérer les trois failles d'injection (SQLi, stored XSS, command injection) dans un fichier de routes réel, et les réécrire en version sûre — paramétrée, encodée, sans shell.
> **Vrai outil :** un projet Node/TypeScript avec `pg` (PostgreSQL), Zod et `node:child_process`. Tu écris et lis du vrai code — pas de gap-fill, pas de harnais auto-correcteur.
> **Feedback :** le coach valide la revue en session (revue de code sécurité orale, comme un vrai audit).

---

## Énoncé

On te confie `family-api.ts`, un fichier de routes du back-office TribuZen. Il **fonctionne** en apparence, mais il contient **trois failles d'injection**. Ton travail d'auditeur défensif :

1. **Identifier** les trois failles (type + ligne + pourquoi c'est exploitable).
2. **Réécrire** chaque route en version sûre.
3. **Justifier** pour chaque correction *quelle couche* la neutralise (paramétrage / encodage / séparation binaire-arguments) — et distinguer la vraie barrière des simples renforts.

> Rappel de posture : ces failles sont dans **ton** code. On les corrige. On ne rédige aucun payload pour attaquer un système que tu ne possèdes pas.

### Code à auditer (starter)

Copie ce fichier dans un projet Node/TS (`npm i pg zod`, `@types/pg`). Tu n'as **pas** besoin d'une vraie base pour l'audit : le raisonnement se fait à la lecture, la version sûre se compile.

```typescript
// family-api.ts — ❌ 3 failles à trouver et corriger
import express from 'express'
import { Pool } from 'pg'
import { exec } from 'node:child_process'

const app = express()
app.use(express.json())
const pool = new Pool()

// Route A — recherche de membres par prénom
app.get('/api/family/:familyId/members', async (req, res) => {
  const { q } = req.query
  const sql = `SELECT id, first_name FROM members
               WHERE family_id = '${req.params.familyId}'
                 AND first_name LIKE '%${q}%'`
  const result = await pool.query(sql)
  res.json(result.rows)
})

// Route B — page HTML listant les commentaires du journal
app.get('/api/journal/:id/html', async (req, res) => {
  const rows = await pool.query(
    'SELECT content FROM comments WHERE journal_id = $1',
    [req.params.id],
  )
  let html = '<ul>'
  for (const row of rows.rows) {
    html += `<li>${row.content}</li>` // content vient d'un parent, stocké tel quel
  }
  html += '</ul>'
  res.send(html)
})

// Route C — vérifie qu'un serveur de sauvegarde répond (ping)
app.get('/api/ops/ping', (req, res) => {
  const { host } = req.query
  exec(`ping -c 2 ${host}`, (err, stdout) => {
    if (err) return res.status(500).json({ error: 'ping failed' })
    res.type('text').send(stdout)
  })
})
```

---

## Étapes (en friction)

1. **Lis chaque route et nomme la faille** avant de coder. Écris à la main : `Route A = ____ , exploitable car ____`. Fais-le pour A, B, C.
2. **Route A (SQLi)** — remplace la concaténation par une requête **paramétrée** (`$1`, `$2`). Le motif `%...%` du `LIKE` se construit côté JS puis passe comme valeur. Ajoute une validation Zod de `q` **en renfort** (string bornée).
3. **Route B (stored XSS)** — la donnée est du texte affiché en HTML. Choisis la bonne défense : si `content` est du texte simple, encode-le ; s'il peut contenir du HTML riche, sanitize avec DOMPurify + allow-list. Décide et justifie ton choix.
4. **Route C (command injection)** — remplace `exec` par `execFile` (pas de shell), arguments en **tableau**. Ajoute une validation allow-list du `host` en renfort.
5. **Rédige ta justification** : pour chaque route, quelle est la **vraie barrière** et quels sont les **renforts** ? (Indice : Zod et CSP ne sont jamais la barrière principale.)
6. **Vérifie** que ta version compile (`npx tsc --noEmit`) et relis-la comme si c'était la PR d'un collègue.

---

## Grille d'auto-évaluation

Coche avant de présenter au coach. Objectif : tout en vert.

| Critère | ❌ | ⚠️ | ✅ |
|---|---|---|---|
| Les 3 failles nommées correctement (SQLi / stored XSS / command injection) | 0-1 trouvée | 2 trouvées | 3 trouvées + type exact |
| Route A : `family_id` **et** `q` en paramètres (pas juste l'un) | concaténation restante | 1 des 2 paramétré | les 2 paramétrés, `%q%` en valeur |
| Route B : défense adaptée au contexte (encodage OU DOMPurify justifié) | HTML brut concaténé | sanitize mais sans allow-list | encodage/DOMPurify + choix justifié |
| Route C : `execFile` sans shell, args en tableau | `exec` gardé | `execFile('sh',['-c',...])` (faux) | `execFile('ping', [...])` |
| Distinction barrière vs renfort explicitée | absente | confuse | claire (Zod/CSP = renfort) |
| Aucune régression : la version sûre compile (`tsc --noEmit`) | ne compile pas | warnings | compile propre |

---

## Corrigé complet commenté

```typescript
// family-api.ts — ✅ version sûre
import express from 'express'
import { Pool } from 'pg'
import { execFile } from 'node:child_process'
import { z } from 'zod'

const app = express()
app.use(express.json())
const pool = new Pool()

// ── Route A — SQLi corrigée par PARAMÉTRAGE (barrière) + Zod (renfort) ──
const SearchSchema = z.object({ q: z.string().min(1).max(50) })

app.get('/api/family/:familyId/members', async (req, res) => {
  // Renfort (couche 2) : borne l'entrée, mais NE remplace pas le paramétrage
  const parsed = SearchSchema.safeParse(req.query)
  if (!parsed.success) return res.status(400).json({ error: 'q invalide' })

  // Barrière (couche 1) : requête paramétrée.
  // family_id ET q sont des VALEURS ($1, $2), jamais du texte SQL.
  // Le %...% est assemblé côté JS puis passé comme valeur → pas d'injection.
  const result = await pool.query(
    `SELECT id, first_name
       FROM members
      WHERE family_id = $1
        AND first_name ILIKE $2`,
    [req.params.familyId, `%${parsed.data.q}%`],
  )
  res.json(result.rows)
})

// ── Route B — stored XSS corrigée par ENCODAGE de sortie ──
// Choix : le commentaire du journal est du TEXTE SIMPLE → on encode.
// (Si on voulait du HTML riche, on passerait par DOMPurify + allow-list.)
function encodeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
}

app.get('/api/journal/:id/html', async (req, res) => {
  const rows = await pool.query(
    'SELECT content FROM comments WHERE journal_id = $1',
    [req.params.id],
  )
  // Chaque content est encodé AVANT insertion dans le HTML.
  // Un < devient &lt; : il s'affiche comme texte, jamais comme balise.
  const items = rows.rows.map((r) => `<li>${encodeHtml(r.content)}</li>`)
  res.send(`<ul>${items.join('')}</ul>`)
  // En pratique : un moteur de template à auto-escaping (ou React côté front)
  // fait cet encodage pour toi. encodeHtml ici rend la barrière explicite.
})

// ── Route C — command injection corrigée par SÉPARATION binaire/arguments ──
// Renfort : un hostname valide matche un motif strict (allow-list)
const HOSTNAME = /^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$/

app.get('/api/ops/ping', (req, res) => {
  const host = req.query.host
  if (typeof host !== 'string' || !HOSTNAME.test(host)) {
    return res.status(400).json({ error: 'host invalide' })
  }
  // Barrière : execFile ne lance PAS de shell. Les métacaractères (; | &&)
  // dans host resteraient un argument littéral, non interprétés.
  execFile('ping', ['-c', '2', host], (err, stdout) => {
    if (err) return res.status(500).json({ error: 'ping failed' })
    res.type('text').send(stdout)
  })
})

export { app }
```

**Pourquoi ce corrigé est correct :**
- **Route A** : la vraie barrière est le paramétrage (`$1`, `$2`) — l'apostrophe dans un prénom comme `O'Brien` redevient un caractère de donnée. Zod est un renfort qui réduit la surface, pas la protection.
- **Route B** : la donnée devient inerte à la **sortie** grâce à l'encodage contextuel (corps HTML). C'est un choix : pour du HTML riche légitime, on remplacerait `encodeHtml` par `DOMPurify.sanitize` avec allow-list. Encoder à la main est ici pédagogique — en vrai, on délègue au framework/template.
- **Route C** : `execFile('ping', [...])` supprime le shell, donc la classe entière de la faille. `execFile('sh', ['-c', cmd])` serait un faux ami (le shell revient). L'allow-list de hostname est un renfort.

---

## Coach — points à challenger en session

Le coach vérifie la **compréhension**, pas juste le code qui compile :

- « Sur la Route A, si je garde **seulement** la validation Zod et que je concatène, suis-je protégé ? » → **Non** : `O'Brien` est une string Zod-valide qui casse une requête concaténée. Le paramétrage est la barrière.
- « Sur la Route B, pourquoi ne pas juste bloquer le mot `script` ? » → Filtrage par blacklist contournable (`<img onerror=...>`, encodages) ; l'encodage de **sortie** contextuel est la bonne réponse.
- « Sur la Route C, `execFile('sh', ['-c', \`ping ${host}\`])` — c'est bon puisque j'utilise execFile ? » → **Non**, le shell est réintroduit. Il faut `execFile('ping', ['-c','2', host])`.
- « Où placerais-tu la CSP et le moindre privilège dans tout ça ? » → Défense en profondeur (couche 3), pour limiter l'impact si une couche cède — jamais en remplacement.

Attendu : Sylvain sait **nommer la barrière vs le renfort** pour chaque route, sans notes.

---

## Variante J+30 (fading)

**Même audit, de mémoire, en 30 minutes, sans rouvrir ce corrigé ni le module 02.** Contraintes ajoutées :

1. On ajoute une **Route D** : `POST /api/family/:id/rename` qui fait `UPDATE families SET name = '<body.name>' WHERE id = '<:id>'` par concaténation. Corrige-la (paramétrage).
2. Sur la **Route B**, le besoin change : les commentaires peuvent désormais contenir du **gras et des liens** (HTML riche). Réécris la défense avec **DOMPurify** + allow-list (`b`, `i`, `strong`, `a[href]`) au lieu de l'encodage brut.
3. Rédige en 3 lignes, pour chaque route (A→D), la phrase : « barrière = ____ ; renfort = ____ ».

**Critère de réussite :** 4 routes sûres, la distinction barrière/renfort correcte pour chacune, le tout sans consulter le corrigé.

---

## Application TribuZen

Dans `smaurier/tribuzen`, ces routes vivent ici :

```
tribuzen/
  src/
    server/
      routes/
        family.ts     ← Route A (recherche paramétrée)
        journal.ts    ← Route B (rendu commentaire, DOMPurify si HTML riche)
        ops.ts        ← Route C (ping via execFile, réservé admin)
```

**Différences avec le lab :**
- La couche DB passe par **Prisma** (API typée) plutôt que du SQL `pg` brut ; les rares raw queries utilisent `$queryRaw` (tagged template paramétré), jamais `$queryRawUnsafe`.
- Le rendu des commentaires se fait **côté front React** : l'encodage est automatique, DOMPurify n'intervient que pour le HTML riche du journal.
- La Route C n'est accessible qu'aux comptes admin (contrôle d'accès — module 04) et le compte DB applicatif est en **moindre privilège**.

**Commit cible :**
```
fix(security): durcit family-api — SQLi paramétrée, XSS encodée, ping via execFile
```
