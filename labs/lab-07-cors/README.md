# Lab 07 — Auditer et durcir une config CORS TribuZen

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

> **Outcome :** à la fin, tu sais **repérer** une config CORS dangereuse (`origin: true` + `credentials: true`), **expliquer** précisément la fuite qu'elle ouvre, et la **corriger** en allowlist explicite avec `Vary: Origin` — le tout vérifié dans un vrai serveur, pas un harnais.
> **Vrai outil :** un serveur **NestJS** (`app.enableCors`) ou **Express** (`cors`), lancé pour de vrai + `curl` et l'onglet Network des DevTools comme oracle.
> **Feedback :** le coach valide en session (pas de test-runner auto-correcteur). Exercice **défensif** : on durcit TA propre API, on n'attaque aucun système tiers.

---

## Énoncé

Tu reprends l'API TribuZen. Front sur `https://app.tribuzen.fr`, API sur `https://api.tribuzen.fr` (origines différentes), session par cookie `__Host-sid` envoyé en `credentials: 'include'`. Un collègue a livré ceci pour « faire taire les erreurs CORS » :

```typescript
// main.ts — config CORS livrée, à AUDITER puis CORRIGER
app.enableCors({
  origin: true,        // reflète n'importe quelle Origin dans Access-Control-Allow-Origin
  credentials: true,   // et autorise le cookie de session avec
})
```

Ta mission, en trois temps :

1. **Auditer** — écris (en 3-5 phrases) *quelle donnée fuit*, *vers qui*, et *pourquoi le spec CORS ne suffit pas à bloquer ici* (indice : le wildcard `*` serait bloqué avec credentials, mais refléter l'Origin contourne cette protection).
2. **Corriger** — remplace la config par une **allowlist explicite** (depuis une variable d'env), qui ne renvoie `Access-Control-Allow-Origin` que pour les origines connues, garde `credentials: true` sans jamais `*`, et laisse le middleware poser `Vary: Origin`.
3. **Prouver** — avec `curl`, montre que la réponse au preflight `OPTIONS` renvoie l'origine exacte pour `app.tribuzen.fr` et **aucun** `Access-Control-Allow-Origin` pour `evil.example`.

**Pas de gap-fill** — tu écris la config complète à partir du starter.

### Starter minimal

```typescript
// main.ts — starter (NestJS). Équivalent Express avec le middleware `cors` accepté.
import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'

// TODO 1 — construire ALLOWED_ORIGINS depuis process.env.CORS_ORIGINS (fallback: prod uniquement)
// TODO 2 — remplacer origin: true par un callback qui COMPARE l'Origin à l'allowlist
// TODO 3 — garder credentials: true, énumérer methods + allowedHeaders, ajouter maxAge

async function bootstrap() {
  const app = await NestFactory.create(AppModule)

  app.enableCors({
    origin: true,      // ← à remplacer
    credentials: true,
  })

  await app.listen(3000)
}
bootstrap()
```

---

## Étapes (en friction)

1. **Rédige l'audit** (temps 1) — nomme la donnée exposée (liste des enfants/activités), l'attaquant (n'importe quel site sur lequel un parent connecté navigue), et le mécanisme (Origin reflété + cookie envoyé → le navigateur autorise la lecture).
2. **Construis l'allowlist** — `const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS ?? 'https://app.tribuzen.fr').split(',').map(o => o.trim())`.
3. **Écris le callback `origin`** — `if (!origin) return cb(null, true)` (curl/mobile/same-origin), puis `cb(null, ALLOWED_ORIGINS.includes(origin))`.
4. **Énumère** `methods` et `allowedHeaders` (`Content-Type`, `Authorization`) ; ajoute `maxAge: 86400`. Ne mets **jamais** `*` puisqu'il y a des credentials.
5. **Lance le serveur** et teste au `curl` :
   - preflight autorisé : `curl -i -X OPTIONS https://api.tribuzen.fr/api/enfants -H "Origin: https://app.tribuzen.fr" -H "Access-Control-Request-Method: POST"` → doit contenir `Access-Control-Allow-Origin: https://app.tribuzen.fr` + `Vary: Origin`.
   - origine refusée : même commande avec `-H "Origin: https://evil.example"` → **aucun** `Access-Control-Allow-Origin`.
6. **Vérifie le point clé de sécurité** — depuis un terminal, `curl https://api.tribuzen.fr/api/enfants -H "Cookie: __Host-sid=..."` reçoit quand même la réponse : c'est **normal**, CORS ne protège pas du curl. Note en une phrase que la vraie barrière est l'**authZ** (module 04), pas CORS.

---

## Corrigé complet commenté

```typescript
// main.ts — corrigé
import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'

// Allowlist explicite depuis l'env : dev peut ajouter localhost, prod = app.tribuzen.fr seul.
// JAMAIS origin: true en prod — ça reflète toute origine (le bug de départ).
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS ?? 'https://app.tribuzen.fr')
  .split(',')
  .map((o) => o.trim())

async function bootstrap() {
  const app = await NestFactory.create(AppModule)

  app.enableCors({
    // Le callback COMPARE l'Origin reçue à l'allowlist — il ne la reflète pas aveuglément.
    origin: (origin, callback) => {
      // Requêtes sans Origin (curl, app mobile, same-origin) : CORS ne les concerne pas.
      // Leur sécurité vient de l'authN/authZ côté serveur, pas d'ici.
      if (!origin) return callback(null, true)

      // Dans l'allowlist → le middleware renverra CETTE origine (jamais "*").
      // Hors allowlist → false : pas d'en-tête Allow-Origin → le navigateur bloque la lecture.
      callback(null, ALLOWED_ORIGINS.includes(origin))
    },
    credentials: true,                 // cookie __Host-sid envoyé → "*" serait illégal, d'où l'allowlist
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400,                     // cache preflight 24 h → moins de requêtes OPTIONS
    // Vary: Origin ajouté automatiquement par le middleware quand origin est dynamique.
  })

  await app.listen(3000)
}
bootstrap()
```

**Audit attendu (temps 1) :**
> `origin: true` renvoie en écho l'`Origin` de chaque requête dans `Access-Control-Allow-Origin`. Avec `credentials: true`, tout site (`evil.example`) sur lequel un parent **connecté** navigue peut faire un `fetch` vers l'API **avec le cookie de session du parent** et **lire** la réponse — donc la liste des enfants et leurs activités (données de mineurs). Le spec interdit `Access-Control-Allow-Origin: *` avec credentials, mais **refléter l'Origin** contourne cette protection en donnant à chaque attaquant sa propre origine « autorisée ». La correction est une **allowlist** comparée explicitement.

**Pourquoi ce corrigé est correct :**
- L'`Origin` est **comparée** à une liste connue, jamais reflétée aveuglément → un site non listé ne reçoit aucun `Access-Control-Allow-Origin`, le navigateur bloque la lecture.
- `credentials: true` est désormais **sûr** car couplé à une origine unique et vérifiée (pas de `*`, pas de reflet).
- `Vary: Origin` (posé par le middleware) empêche un cache partagé de servir la mauvaise valeur d'`Allow-Origin`.
- **Rappel non négociable :** cette config protège l'utilisateur du **navigateur**. Elle ne remplace pas l'authZ : un `curl` avec un cookie volé reçoit toujours la réponse — c'est le contrôle d'accès serveur (module 04) qui doit vérifier que *ce* parent a le droit de voir *cette* famille.

---

## Grille d'auto-évaluation

| Critère | Acquis si… |
|---|---|
| Audit de la fuite | tu nommes la **donnée** exposée (liste enfants/activités), **vers qui** (tout site où un parent connecté navigue) et **le mécanisme** (Origin reflété + cookie envoyé) |
| Pourquoi `*` ne « sauve » pas | tu expliques que le spec interdit `*` **avec credentials**, mais que **refléter l'Origin** contourne cette protection — d'où l'allowlist |
| Allowlist explicite | l'Origin est **comparée** à une liste (depuis l'env), jamais reflétée aveuglément ; hors liste → **aucun** `Access-Control-Allow-Origin` |
| Credentials sûrs | `credentials: true` est conservé **sans** jamais `*`, couplé à une origine unique vérifiée |
| `Vary: Origin` | présent, et tu sais pourquoi (un cache partagé ne doit pas servir la mauvaise valeur d'`Allow-Origin`) |
| Preuve au curl | preflight `OPTIONS` renvoie l'origine exacte pour `app.tribuzen.fr` et **rien** pour `evil.example` (exécuté, pas supposé) |
| CORS ≠ authZ | tu montres qu'un `curl` avec cookie reçoit quand même la réponse et nommes le module 04 comme vraie barrière |

**Seuil :** « Acquis » sur l'audit de la fuite, l'allowlist explicite et « CORS ≠ authZ » — comprendre la faille, la fermer, et savoir ce que CORS ne protège pas.

---

## Coach — conduite de session

- **Fais rédiger l'audit AVANT de toucher au code.** Trois phrases : quelle donnée, vers qui, par quel mécanisme. Si Sylvain saute direct à `cors({ origin: [...] })`, il aura corrigé sans comprendre la fuite.
- **Piège à débusquer #1 — « il suffit d'interdire `*` » :** relance : « le collègue n'a pas mis `*`, il a mis `origin: true`. Pourquoi c'est **pire** ? ». La réponse (reflet d'Origin = chaque attaquant a sa propre origine autorisée) est le cœur du lab.
- **Piège à débusquer #2 — allowlist par `startsWith`/regex laxiste :** s'il matche `app.tribuzen.fr` avec un `includes`/`endsWith`, teste `app.tribuzen.fr.evil.example`. La comparaison doit être **exacte**.
- **Piège à débusquer #3 — confondre CORS et authZ :** fais-lui lancer le `curl` avec cookie qui reçoit quand même la réponse. Le déclic « CORS protège le navigateur, pas l'API » doit être vécu, pas récité.
- **Ancrage TribuZen :** la donnée qui fuit, c'est la **liste des enfants et leurs activités**. L'attaquant n'a même pas besoin de voler le cookie — le navigateur du parent l'envoie tout seul. Rends la menace concrète.
- **Si silence / blocage :** pars du `curl` de preuve (origine listée vs `evil.example`) et fais-lui déduire la config qui produit ces deux réponses. L'oracle observable débloque la théorie.

---

## Variante J+30 (fading)

**Même objectif, contraintes ajoutées** — de mémoire, en 20 minutes, sans rouvrir ce corrigé ni le module 07 :

1. Repars du starter `origin: true` et durcis-le en allowlist **multi-origines** (`https://app.tribuzen.fr` **et** `http://localhost:5173` pour le dev), pilotée par `CORS_ORIGINS`.
2. Ajoute un scénario **preflight** : le front doit envoyer un en-tête custom `X-Tribu-Trace`. Fais échouer volontairement le preflight (oublie l'en-tête dans `allowedHeaders`), observe l'erreur `OPTIONS` dans le Network, puis corrige.
3. En une phrase, explique pourquoi durcir CORS **ne suffit pas** à protéger `/api/enfants` et cite le module qui apporte la vraie barrière.

**Critère de réussite :** le preflight renvoie l'origine exacte + `X-Tribu-Trace` autorisé pour une origine listée, rien pour une origine hors liste, et tu peux réciter « CORS assouplit la SOP côté navigateur, l'authZ serveur reste requise ».

---

## Application TribuZen

Dans `smaurier/tribuzen` (API NestJS), la config CORS vit ici :

```
tribuzen-api/
  src/
    main.ts                  ← app.enableCors({ origin: allowlist, credentials: true, ... })
    config/
      cors.config.ts         ← ALLOWED_ORIGINS depuis env (dev: +localhost ; prod: app.tribuzen.fr)
    common/guards/           ← authN/authZ : la VRAIE barrière (module 03/04), indépendante de CORS
```

**Différences par rapport au lab :**
- L'allowlist sort dans `config/cors.config.ts` et est injectée via `ConfigService` plutôt que lue directement dans `main.ts`.
- Les origines prod/staging/dev viennent de variables d'env par environnement (`.env`, secrets CI) — jamais codées en dur.
- Le durcissement CORS est fait **en même temps** que la revue d'authZ des endpoints `/api/enfants` — l'un ne remplace pas l'autre.

**Commit cible :**
```
fix(security): CORS en allowlist explicite + credentials (remplace origin:true dangereux)
```
