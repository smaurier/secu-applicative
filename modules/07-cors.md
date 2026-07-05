---
titre: CORS & Same-Origin Policy — assouplir sans ouvrir la porte
cours: 14-securite-applicative
notions: ["Same-Origin Policy (origine = protocole + hôte + port)", "requête simple vs preflight OPTIONS", "en-tête `Access-Control-Allow-Origin`", "en-tête `Access-Control-Allow-Credentials: true`", "en-tête `Access-Control-Allow-Methods`", "en-tête `Access-Control-Allow-Headers`", "règle wildcard `*` interdit avec credentials", "reflecting Origin sans allowlist = anti-pattern", "en-tête `Vary: Origin`", "CORS assouplit la SOP, ne protège PAS le serveur"]
outcomes:
  - "sait définir une origine (protocole + hôte + port) et dire ce que la Same-Origin Policy bloque vs autorise"
  - "sait distinguer une requête simple d'une requête déclenchant un preflight OPTIONS, et lire les en-têtes Access-Control-Request-*"
  - "sait configurer les en-têtes CORS corrects (Allow-Origin par allowlist, Allow-Credentials, Allow-Methods, Allow-Headers, Vary: Origin)"
  - "sait repérer et corriger une config CORS dangereuse (wildcard + credentials, reflecting Origin sans allowlist)"
  - "sait expliquer pourquoi CORS n'est PAS un contrôle d'accès serveur et que l'authZ reste requise"
prerequis:
  - "Introduction sécurité — modèle de menace, defense in depth (module 00)"
  - "Authentification — sessions, cookies HttpOnly/Secure/SameSite (module 03)"
  - "Autorisation — contrôle d'accès côté serveur (module 04)"
  - "Headers de sécurité — cookies, en-têtes HTTP de réponse (module 06)"
next: 08-api-security
libs: []
tribuzen: API TribuZen (NestJS) consommée cross-origin par le front (login, données famille/enfants)
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# CORS & Same-Origin Policy — assouplir sans ouvrir la porte

> **Outcomes — tu sauras FAIRE :** définir une origine et ce que bloque la Same-Origin Policy, distinguer requête simple et preflight, configurer les en-têtes CORS corrects par allowlist, repérer et corriger une config permissive dangereuse, et expliquer pourquoi CORS ne remplace **jamais** l'autorisation serveur.
> **Difficulté :** :star::star::star:
>
> **Angle : DÉFENSIF.** On montre les failles de config pour les **comprendre et les corriger** dans TON serveur, jamais pour attaquer un tiers.
>
> **Portée :** ce module couvre la **Same-Origin Policy (SOP)** et **CORS** — le mécanisme par lequel un serveur autorise des origines précises à *lire* ses réponses depuis un navigateur. L'**authentification** (cookies, sessions) est le module 03, l'**autorisation** (qui a le droit de faire quoi) le module 04, les **autres en-têtes de sécurité** (CSP, HSTS, SameSite) le module 06, et la **sécurité d'API** au sens large (rate limiting, JWT, validation) le module 08. Point d'ancrage permanent du module : **CORS assouplit la SOP côté navigateur, il ne protège pas le serveur.**

## 1. Cas concret d'abord

Tu reprends l'API TribuZen. Le front (`https://app.tribuzen.fr`) et l'API (`https://api.tribuzen.fr`) sont sur deux **origines différentes** (hôtes différents). Le login pose un cookie de session `__Host-` et le front l'envoie en `credentials: 'include'`. En dev, un collègue a « fait taire les erreurs CORS » comme ça :

```typescript
// main.ts — config CORS livrée. NE PAS copier en prod : elle est dangereuse.
app.enableCors({
  origin: true,        // (1) reflète N'IMPORTE QUELLE origine dans Access-Control-Allow-Origin
  credentials: true,   // (2) et autorise l'envoi du cookie de session avec
})
```

Ça « marche » : plus aucune erreur dans la console. Mais cette config manipule des **données de mineurs** avec une porte grande ouverte.

**Le problème que ce module va corriger :**

`origin: true` dit au middleware de **renvoyer en écho l'`Origin` de la requête** dans `Access-Control-Allow-Origin`, quelle qu'elle soit. Combiné à `credentials: true`, cela signifie : *n'importe quel site* (`https://evil.example`) sur lequel un parent connecté navigue peut faire un `fetch` vers `api.tribuzen.fr` **avec le cookie de session du parent**, et **lire la réponse** (la liste des enfants, les activités…). Le navigateur, voyant `Access-Control-Allow-Origin: https://evil.example` + `Access-Control-Allow-Credentials: true`, laisse le script malveillant lire des données privées.

La règle du spec CORS **interdit** le wildcard `*` avec les credentials — mais **refléter l'Origin** contourne cette protection en donnant à chaque attaquant sa propre origine « autorisée ». C'est l'anti-pattern n°1 de CORS.

À la fin du module, cette config passe à une **allowlist explicite** (`app.tribuzen.fr` uniquement), avec `Vary: Origin`, et tu sauras dire pourquoi CORS ne dispense **jamais** de vérifier l'authZ côté serveur. C'est le fil rouge du lab.

---

## 2. Théorie complète, concise

### 2.1 Same-Origin Policy : la règle par défaut du navigateur

La **Same-Origin Policy (SOP)** est la politique de sécurité fondamentale du navigateur. Par défaut, un script d'une origine ne peut **pas lire** la réponse d'une requête programmatique (`fetch`, `XMLHttpRequest`) vers une **autre origine**.

Une **origine** = triplet **protocole + hôte + port**. Les trois doivent être identiques.

Référence : `https://app.tribuzen.fr` (port 443 implicite)

| URL comparée | Même origine ? | Raison |
|---|---|---|
| `https://app.tribuzen.fr/dashboard` | ✅ oui | seul le chemin diffère |
| `http://app.tribuzen.fr` | ❌ non | protocole différent (http vs https) |
| `https://api.tribuzen.fr` | ❌ non | hôte différent |
| `https://app.tribuzen.fr:8443` | ❌ non | port différent |

**Ce que la SOP restreint :** la **lecture** des réponses cross-origin par du JS. Le front sur `app.` ne peut pas lire ce que renvoie `api.` **sans autorisation explicite** du serveur.

**Ce que la SOP n'empêche pas** (chargement passif de ressources, sans lecture du contenu par JS) :

- `<img src="…">`, `<script src="…">`, `<link rel="stylesheet">`, `<video>`/`<audio>`, `@font-face`, `<iframe>`.
- Les **écritures** cross-origin (soumettre un formulaire, suivre un lien) partent aussi — c'est précisément pourquoi le **CSRF** existe (un formulaire malveillant peut *envoyer* une requête ; il ne peut juste pas *lire* la réponse). CSRF est traité via `SameSite` + jetons anti-CSRF (module 06/08), **pas** par CORS.

> Distinction clé : la SOP bloque la **lecture** du résultat, pas l'**envoi** de la requête. CORS lève cette restriction de lecture ; il ne bloque pas l'envoi.

### 2.2 CORS : un assouplissement contrôlé de la SOP

**CORS** (Cross-Origin Resource Sharing) est le mécanisme par lequel un **serveur** déclare, via des en-têtes de réponse, quelles origines ont le droit de **lire** ses réponses depuis un navigateur.

```
┌──────────────────────┐   fetch (credentials: include)   ┌─────────────────────┐
│  app.tribuzen.fr      │ ───────────────────────────────► │  api.tribuzen.fr     │
│  (front, origine A)   │                                   │  (API, origine B)    │
│                       │ ◄─────────────────────────────── │  Access-Control-     │
│  navigateur : lecture │   Access-Control-Allow-Origin:    │  Allow-* headers     │
│  autorisée ? oui/non  │   https://app.tribuzen.fr         │                      │
└──────────────────────┘                                   └─────────────────────┘
```

C'est le **navigateur** qui applique la décision. Un client hors navigateur (curl, Postman, script serveur) **ignore totalement CORS** (voir §2.7).

### 2.3 Requête simple vs preflight

Le navigateur classe la requête cross-origin en deux catégories.

**Requête simple** — envoyée directement (avec l'en-tête `Origin`), sans preflight, si elle remplit **toutes** ces conditions (vérifié MDN 2026-07) :

- **Méthode** : `GET`, `HEAD` ou `POST`.
- **En-têtes** : uniquement des en-têtes « CORS-safelisted » — `Accept`, `Accept-Language`, `Content-Language`, `Content-Type`, `Range` (valeur simple).
- **`Content-Type`** : uniquement `application/x-www-form-urlencoded`, `multipart/form-data` ou `text/plain`.
- Pas de listener sur `XMLHttpRequest.upload`, pas de `ReadableStream` dans la requête.

> Conséquence pratique : un `POST` en `Content-Type: application/json` **n'est PAS simple** → il déclenche un preflight. La majorité des appels d'API JSON authentifiés passent donc par un preflight.

**Requête preflight** — pour tout ce qui n'est pas simple, le navigateur envoie d'abord une requête `OPTIONS` de contrôle :

```http
OPTIONS /api/enfants HTTP/1.1
Host: api.tribuzen.fr
Origin: https://app.tribuzen.fr
Access-Control-Request-Method: POST
Access-Control-Request-Headers: content-type
```

Le serveur répond en déclarant ce qu'il autorise :

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.tribuzen.fr
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
Vary: Origin
```

Si le preflight est accepté, le navigateur envoie **ensuite** la vraie requête. Sinon : erreur CORS, la vraie requête n'est **jamais** envoyée.

```
requête cross-origin
        │
   simple ? ──oui──►  envoi direct (avec Origin) ──► réponse lue si Allow-Origin correspond
        │
        non
        │
   OPTIONS preflight ──► serveur répond Allow-* ──► accepté ? ──oui──► vraie requête
                                                        │
                                                       non ──► ERREUR CORS (rien n'est envoyé)
```

### 2.4 Les en-têtes de réponse CORS (exacts, vérifiés MDN 2026-07)

| En-tête | Rôle | Exemple |
|---|---|---|
| `Access-Control-Allow-Origin` | origine autorisée à **lire** la réponse — une seule origine, ou `*` | `Access-Control-Allow-Origin: https://app.tribuzen.fr` |
| `Access-Control-Allow-Credentials` | autorise l'envoi/lecture avec cookies & auth | `Access-Control-Allow-Credentials: true` |
| `Access-Control-Allow-Methods` | méthodes autorisées (réponse au preflight) | `Access-Control-Allow-Methods: GET, POST, PUT, DELETE` |
| `Access-Control-Allow-Headers` | en-têtes de requête autorisés (réponse au preflight) | `Access-Control-Allow-Headers: Content-Type, Authorization` |
| `Access-Control-Max-Age` | durée (s) de cache du preflight par le navigateur | `Access-Control-Max-Age: 86400` |
| `Access-Control-Expose-Headers` | en-têtes de réponse que le JS a le droit de **lire** | `Access-Control-Expose-Headers: X-Total-Count` |

`Access-Control-Allow-Origin` ne peut lister **qu'une seule** origine (ou `*`). Pour supporter plusieurs origines, on compare l'`Origin` reçu à une **allowlist** et on renvoie **dynamiquement** l'origine correspondante — ce qui impose `Vary: Origin` (§2.6).

### 2.5 La règle critique : wildcard `*` interdit avec les credentials

Citation directe du spec (MDN, vérifié 2026-07) :

> *When responding to a credentialed request, the server must not specify the `*` wildcard for the `Access-Control-Allow-Origin` response-header value, but must instead specify an explicit origin.*

La même interdiction du `*` s'applique à `Access-Control-Allow-Headers`, `Access-Control-Allow-Methods` et `Access-Control-Expose-Headers` dès qu'il y a credentials : il faut **énumérer** explicitement.

Donc, dès qu'une requête porte des cookies ou de l'auth (`credentials: 'include'`) :

- `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` → **le navigateur bloque** (combinaison illégale). C'est une protection du spec.
- La « solution » tentante — **refléter l'`Origin` reçu** dans `Access-Control-Allow-Origin` sans le comparer à une allowlist — **contourne** cette protection : chaque attaquant obtient sa propre origine « autorisée ». **C'est l'anti-pattern à bannir** (le `origin: true` du §1).

**Correct :** comparer l'`Origin` reçu à une **allowlist codée en dur / en config**, et ne renvoyer l'origine que si elle y figure.

### 2.6 `Vary: Origin` : ne pas empoisonner les caches

Quand `Access-Control-Allow-Origin` est calculé **dynamiquement** (selon l'`Origin` reçu), la réponse varie d'un demandeur à l'autre. Sans `Vary: Origin`, un cache (CDN, proxy) pourrait servir à `evil.example` une réponse mise en cache pour `app.tribuzen.fr` (ou l'inverse). `Vary: Origin` force le cache à distinguer les réponses par origine. Les middlewares CORS sérieux (Express `cors`, NestJS) l'ajoutent automatiquement quand l'origine est dynamique.

### 2.7 CORS n'est PAS un contrôle d'accès serveur

**Le point le plus important du module.** CORS est appliqué par le **navigateur**, pour protéger **l'utilisateur** contre du JS malveillant d'autres sites. Il ne protège **pas** le serveur :

- `curl`, Postman, un script Python, un autre serveur → **ignorent CORS**. Ils reçoivent la réponse quelle que soit ta config `Access-Control-Allow-Origin`.
- CORS ne dit **rien** sur *qui a le droit* de faire l'action. Il dit seulement quel *navigateur* peut *lire* la réponse.

```bash
# curl se moque totalement de tes en-têtes CORS : il reçoit la réponse quand même.
curl https://api.tribuzen.fr/api/enfants -H "Cookie: __Host-sid=<jeton volé>"
```

CORS ne remplace donc **jamais** :

- l'**authentification** (le serveur vérifie la session/le token — module 03) ;
- l'**autorisation** (le serveur vérifie que *ce* parent a le droit de voir *cette* famille — module 04) ;
- la **validation** des entrées et le **rate limiting** (module 08).

> Formule à retenir : **CORS assouplit la Same-Origin Policy côté navigateur ; l'authZ côté serveur reste requise, toujours.**

---

## 3. Worked examples

### Exemple 1 — Config CORS durcie pour l'API TribuZen (NestJS)

On reprend le `origin: true` dangereux du §1 et on le remplace par une allowlist.

```typescript
// main.ts — config CORS durcie
import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'

// Allowlist explicite : depuis l'env, jamais "reflète tout".
// En dev on ajoute localhost ; en prod, seulement le vrai domaine.
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS ?? 'https://app.tribuzen.fr')
  .split(',')
  .map((o) => o.trim())

async function bootstrap() {
  const app = await NestFactory.create(AppModule)

  app.enableCors({
    // Callback : on COMPARE l'Origin reçue à l'allowlist, on ne la reflète pas aveuglément.
    origin: (origin, callback) => {
      // Pas d'Origin (curl, app mobile, same-origin) → laisser passer : CORS ne les concerne pas.
      // La sécurité de CES requêtes vient de l'authN/authZ, pas de CORS.
      if (!origin) return callback(null, true)

      if (ALLOWED_ORIGINS.includes(origin)) {
        callback(null, true)          // → le middleware renvoie CET origin (pas "*")
      } else {
        callback(null, false)         // refusé : pas d'en-tête Allow-Origin → navigateur bloque
      }
    },
    credentials: true,                 // cookie de session envoyé — donc PAS de "*" possible
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400,                     // cache preflight 24 h : moins d'OPTIONS
    // Le middlware NestJS/cors ajoute Vary: Origin automatiquement quand origin est dynamique.
  })

  await app.listen(3000)
}
bootstrap()
```

Ce qui a changé vs le §1 :
- `origin: true` (reflète tout) → **allowlist** comparée explicitement.
- Une origine hors liste ne reçoit **aucun** `Access-Control-Allow-Origin` → le navigateur bloque la lecture.
- `credentials: true` reste, mais il est désormais **sûr** car couplé à une origine unique et vérifiée.
- `Vary: Origin` géré par le middleware (réponse dynamique).

### Exemple 2 — Lire ce qui se passe dans les DevTools

Le front fait ce `fetch` authentifié :

```typescript
// front — appel JSON authentifié : NON simple → preflight OPTIONS d'abord
await fetch('https://api.tribuzen.fr/api/enfants', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }, // Content-Type json → déclenche le preflight
  credentials: 'include',                           // envoie le cookie __Host-sid
  body: JSON.stringify({ prenom: 'Léa' }),
})
```

Dans l'onglet **Network**, tu vois **deux** requêtes :

1. `OPTIONS /api/enfants` (le preflight). Réponse attendue :
   ```http
   HTTP/1.1 204 No Content
   Access-Control-Allow-Origin: https://app.tribuzen.fr   ← l'origine exacte, pas *
   Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE
   Access-Control-Allow-Headers: Content-Type, Authorization
   Access-Control-Allow-Credentials: true
   Vary: Origin
   ```
2. `POST /api/enfants` (la vraie requête), envoyée **seulement si** le preflight a été accepté.

**Diagnostic express** d'une erreur CORS : regarde d'abord la requête **OPTIONS**. Si `Access-Control-Allow-Origin` est absent, ou vaut `*` alors qu'il y a des credentials, ou ne correspond pas à ton origine → c'est là qu'est le bug, côté **serveur**.

---

## 4. Pièges & misconceptions

### PIÈGE #1 — « J'ai mis `Access-Control-Allow-Origin: *`, c'est réglé »
Faux dès qu'il y a des credentials : `*` + `Access-Control-Allow-Credentials: true` est une **combinaison illégale**, le navigateur bloque. `*` ne convient que pour des ressources **publiques sans cookies** (une API ouverte en lecture seule). Pour une API à session, il faut une **origine explicite**.

### PIÈGE #2 — Refléter l'`Origin` pour « supporter plusieurs domaines »
`Access-Control-Allow-Origin: <Origin reçu>` sans allowlist **contourne** la protection du spec : chaque site attaquant devient sa propre origine autorisée. Avec `credentials: true`, c'est équivalent à ouvrir l'API à tout le web authentifié. Correct : **allowlist** comparée explicitement (`origin: true` de NestJS et `origin: (o,cb)=>cb(null,true)` font exactement ce reflet — à bannir).

### PIÈGE #3 — Croire que CORS protège le serveur
CORS protège l'**utilisateur du navigateur**, pas le serveur. `curl`/Postman/un backend ignorent CORS et reçoivent la réponse. Une config CORS stricte **ne dispense jamais** d'authN + authZ + validation côté serveur. Serrer CORS n'a **aucun** effet sur un attaquant hors navigateur.

### PIÈGE #4 — Confondre CORS et CSRF
Ce sont deux choses opposées. La SOP **laisse partir** les écritures cross-origin (formulaires) → d'où le CSRF, mitigé par `SameSite` + jeton anti-CSRF (module 06/08). CORS régit la **lecture** des réponses. Assouplir CORS n'ouvre pas de CSRF ; mais une config CORS credentials trop laxiste peut, elle, exposer des **lectures** de données privées.

### PIÈGE #5 — Oublier `Vary: Origin` avec une origine dynamique
Si tu calcules `Access-Control-Allow-Origin` selon l'`Origin` reçu sans `Vary: Origin`, un cache partagé (CDN/proxy) peut servir la mauvaise valeur d'`Allow-Origin` à un autre demandeur. Toujours `Vary: Origin` quand la réponse dépend de l'origine (les middlewares sérieux le font seuls).

### PIÈGE #6 — Le preflight `OPTIONS` renvoie 401/redirection
Le navigateur envoie l'`OPTIONS` **sans** cookies d'auth applicatifs. Si un guard/middleware d'auth intercepte l'`OPTIONS` et répond 401 ou redirige, le preflight échoue et la vraie requête ne part jamais. Le handler CORS/OPTIONS doit répondre **avant** l'auth (204 + en-têtes), sur toutes les routes concernées.

### PIÈGE #7 — Un `POST application/json` est « simple »
Non : `Content-Type: application/json` sort de la liste `x-www-form-urlencoded` / `multipart/form-data` / `text/plain` → **preflight obligatoire**. La plupart des appels d'API JSON authentifiés déclenchent donc un `OPTIONS` — normal, ce n'est pas un bug.

---

## 5. Ancrage TribuZen

TribuZen sépare le **front** (`app.tribuzen.fr`) de l'**API** (`api.tribuzen.fr`) : deux origines, donc CORS est **structurellement** dans le chemin de chaque appel authentifié. Comme l'API sert des **données de mineurs**, une config permissive n'est pas une gêne cosmétique mais une **fuite de données** potentielle.

Où ça vit dans `smaurier/tribuzen` (API NestJS) :

```
tribuzen-api/
  src/
    main.ts                    ← app.enableCors({ origin: allowlist, credentials: true, ... })
    config/
      cors.config.ts           ← ALLOWED_ORIGINS depuis env (dev: localhost ; prod: app.tribuzen.fr)
    common/
      guards/                   ← authN/authZ : la VRAIE barrière (module 03/04), indépendante de CORS
```

Points d'ancrage concrets :
- **Allowlist par environnement** : `CORS_ORIGINS` en variable d'env — jamais `origin: true` en prod.
- **Credentials** : le cookie `__Host-sid` impose une origine unique → `credentials: true` + allowlist, jamais `*`.
- **Preflight** : les `POST/PUT/PATCH` JSON déclenchent un `OPTIONS` ; le handler CORS répond avant l'auth.
- **Rappel d'équipe** : CORS serré ≠ API sécurisée. La liste des enfants d'une famille est protégée par l'**authZ** (module 04), pas par CORS. Un audit qui « valide CORS » sans vérifier l'authZ passe à côté de l'essentiel.

---

## 6. Points clés

1. **Origine = protocole + hôte + port** ; la Same-Origin Policy bloque par défaut la **lecture** JS des réponses cross-origin (pas leur envoi).
2. **CORS** = le serveur déclare, par en-têtes de réponse, quelles origines peuvent **lire** ses réponses ; c'est le **navigateur** qui applique.
3. **Requête simple** (`GET`/`HEAD`/`POST`, en-têtes safelisted, `Content-Type` limité) = pas de preflight ; sinon **preflight `OPTIONS`** avant la vraie requête. Un `POST application/json` déclenche un preflight.
4. En-têtes clés : `Access-Control-Allow-Origin`, `-Allow-Credentials`, `-Allow-Methods`, `-Allow-Headers`, `-Max-Age`, `-Expose-Headers`.
5. **Wildcard `*` interdit avec credentials** : il faut une **origine explicite** ; `-Allow-Headers/-Methods/-Expose-Headers` doivent aussi être énumérés avec credentials.
6. **Refléter l'`Origin` sans allowlist = anti-pattern** (contourne la protection du spec) ; corriger avec une **allowlist** comparée + `Vary: Origin` quand l'origine est dynamique.
7. **CORS n'est PAS un contrôle d'accès serveur** : curl/Postman/backends l'ignorent. L'**authN + authZ + validation** côté serveur restent **toujours** requises.

---

## 7. Seeds Anki

```
Comment définit-on une origine, et que bloque la Same-Origin Policy ?|Origine = triplet protocole + hôte + port (les trois identiques). La SOP bloque par défaut la LECTURE par du JS des réponses de requêtes cross-origin (fetch/XHR) ; elle ne bloque pas l'envoi de la requête ni le chargement passif de ressources (img, script, iframe).
Quand une requête cross-origin déclenche-t-elle un preflight OPTIONS ?|Dès qu'elle n'est PAS "simple" : méthode autre que GET/HEAD/POST, en-tête non safelisted (ex. Authorization), ou Content-Type autre que x-www-form-urlencoded / multipart/form-data / text/plain. Un POST en application/json déclenche donc un preflight.
Quelle est la règle sur le wildcard * et les credentials en CORS ?|Access-Control-Allow-Origin: * est INTERDIT avec Access-Control-Allow-Credentials: true (le navigateur bloque). Avec credentials, il faut une origine explicite, et Allow-Headers/Allow-Methods/Expose-Headers doivent aussi être énumérés (pas *).
Pourquoi "refléter l'Origin reçu" est-il un anti-pattern CORS ?|Renvoyer l'Origin reçu dans Access-Control-Allow-Origin sans le comparer à une allowlist contourne la protection anti-wildcard : chaque site attaquant devient sa propre origine autorisée. Avec credentials, ça expose les lectures de données privées. Correct : allowlist explicite.
Pourquoi CORS ne protège-t-il PAS le serveur ?|CORS est appliqué par le NAVIGATEUR pour protéger l'utilisateur. curl, Postman, un script ou un autre serveur ignorent CORS et reçoivent la réponse quand même. L'authN + authZ + validation côté serveur restent toujours requises.
À quoi sert Vary: Origin dans une réponse CORS ?|Quand Access-Control-Allow-Origin est calculé dynamiquement selon l'Origin reçu, Vary: Origin empêche un cache partagé (CDN/proxy) de servir la mauvaise valeur d'Allow-Origin à un autre demandeur. Obligatoire dès que la réponse dépend de l'origine.
Quels en-têtes le navigateur envoie-t-il dans un preflight OPTIONS ?|Origin (toujours), Access-Control-Request-Method (la méthode de la vraie requête) et Access-Control-Request-Headers (les en-têtes non-safelisted prévus). Le serveur répond avec Access-Control-Allow-Origin/-Methods/-Headers/-Credentials.
Différence entre CORS et CSRF ?|La SOP LAISSE partir les écritures cross-origin (formulaires) → d'où le CSRF, mitigé par SameSite + jeton anti-CSRF. CORS régit la LECTURE des réponses cross-origin. Assouplir CORS n'ouvre pas de CSRF ; mais une config CORS credentials laxiste expose des lectures de données privées.
```

---

## Pont vers le lab

> Lab associé : `labs/lab-07-cors/README.md`. Exercice **défensif** : auditer une config CORS TribuZen permissive (`origin: true` + `credentials: true`), expliquer la fuite, puis la durcir en allowlist explicite avec `Vary: Origin`. Vrai serveur NestJS/Express, pas de harnais simulé. Corrigé commenté + variante J+30.
