<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Lab 10 — Durcir l'infrastructure de TribuZen

> **Outcome :** à la fin, tu sais sortir les secrets de TribuZen de git (et gérer une clé déjà fuitée), durcir un `docker-compose` (non-root, secrets montés, DB non exposée), configurer un TLS auto-renouvelé au reverse proxy, et poser un journal de sécurité qui logge les bons événements sans fuiter.
> **Vrai outil :** un vrai dépôt + `docker-compose.yml` + `Caddyfile` + un logger `pino` — pas de harnais simulé, pas d'auto-correcteur.
> **Feedback :** le coach valide la config en session (revue du diff + questions), il n'y a pas de test-runner.
>
> **Angle : DÉFENSIF.** Tu durcis TON infra. Aucune attaque contre un tiers : ici on ferme des portes.

---

## Énoncé

On te confie l'infra de démo de TribuZen, dans l'état laissé par un collègue. Elle « tourne » mais elle est trouée. Voici le point de départ **exact** — recopie-le dans un dossier `tribuzen-infra/` :

```yaml
# docker-compose.yml — état de départ (troué, NE PAS déployer)
services:
  api:
    image: tribuzen-api:latest
    user: root
    environment:
      DATABASE_URL: postgres://admin:S3cret@db:5432/tribuzen
      JWT_SECRET: dev-secret-please-change
    ports:
      - "3000:3000"
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: S3cret
    ports:
      - "5432:5432"
```

```bash
# .env — committé dans le dépôt (à corriger)
STRIPE_SECRET_KEY=sk_live_<CLE-EXEMPLE-FICTIVE-NE-JAMAIS-COMMITTER>
SENTRY_DSN=https://abc@o123.ingest.sentry.io/456
```

**Ta mission (4 volets défensifs) :**

1. **Secrets hors git** — mettre en place `.gitignore`, `.env.example`, et **écrire la procédure de révocation** de la clé Stripe déjà committée (dans le bon ordre).
2. **Durcir le compose** — process non-root, secrets montés en fichier (plus dans `environment`), FS en lecture seule, et **DB non joignable depuis l'extérieur**.
3. **TLS auto-renouvelé** — ajouter un reverse proxy (Caddy) qui termine le TLS, force HTTPS + HSTS, et gère ACME tout seul ; l'api ne publie plus aucun port.
4. **Journal de sécurité** — configurer un logger `pino` qui journalise les bons événements (échec de login, 403, rate limit) **avec redaction** des champs sensibles, et lister ce qu'il ne faut JAMAIS logger.

**Pas de gap-fill** : tu écris les fichiers complets à partir du point de départ.

---

## Étapes (en friction)

1. **`.gitignore` + `.env.example`** — ignore `.env`, `secrets/`, `*.pem`. Écris un `.env.example` avec la **structure** des variables mais **zéro valeur réelle**.
2. **Procédure de révocation** — dans un `INCIDENT.md`, écris les étapes pour la `STRIPE_SECRET_KEY` déjà committée, **dans l'ordre**. Pose-toi la question : purger l'historique suffit-il ? Pourquoi la première action n'est-elle pas `git rm` ?
3. **Secrets Docker** — déplace `db_password` et `jwt_secret` dans un bloc `secrets:` monté depuis `./secrets/*.txt` (gitignoré). Retire-les de `environment`. Fais lire l'api dans `/run/secrets/`.
4. **Moindre privilège** — passe l'api en utilisateur non-root (`user:`), ajoute `read_only: true` + `tmpfs: ["/tmp"]`. **Supprime le `ports:` de la DB** (elle ne doit être joignable que par l'api).
5. **Reverse proxy TLS** — ajoute un service `caddy` avec un `Caddyfile` : redirection HTTP→HTTPS, en-tête HSTS, `reverse_proxy` vers `api:3000`. Retire le `ports:` public de l'api.
6. **Logger de sécurité** — écris `logger.ts` avec `pino` + `redact` sur `authorization`, `password`, `*.token`. Journalise `failed_login`, `forbidden_access`, `rate_limit` avec un contexte non sensible.
7. **Vérifie la surface** — relis ton compose : quels ports sont encore publiés ? (réponse attendue : uniquement 80/443 du proxy). Qui peut lire les secrets ? Qui tourne en root ? (réponse attendue : personne).
8. **Cas limite** — que se passe-t-il si `JWT_SECRET` est absent au démarrage ? Ajoute une validation Zod qui **crash au boot** plutôt que de laisser tourner l'app sans secret.

---

## Corrigé complet commenté

**1 — `.gitignore` + `.env.example`**

```bash
# .gitignore — les secrets ne touchent jamais git
.env
.env.*.local
secrets/
*.pem
*.key
```

```bash
# .env.example — COMMITTÉ : structure sans valeurs (placeholders explicites)
DATABASE_URL=postgres://user:password@localhost:5432/tribuzen
JWT_SECRET=change-me-32-chars-minimum
STRIPE_SECRET_KEY=sk_test_xxx
SENTRY_DSN=https://<key>@<org>.ingest.sentry.io/<project>
```

**2 — `INCIDENT.md` : révoquer la clé Stripe committée**

```markdown
# Incident — STRIPE_SECRET_KEY committée

L'ordre est le message : révoquer AVANT de purger.

1. RÉVOQUER / rouler la clé sur le dashboard Stripe.  ← action n°1, non négociable.
   La clé est compromise dès qu'elle a touché l'historique : n'importe quel
   clone/backup la contient déjà. La supprimer de git ne la protège pas.
2. Ajouter `.env` au `.gitignore`, committer `.env.example`.
3. Purger l'historique : `git filter-repo --path .env --invert-paths`
   puis `git push --force-with-lease` (concertation équipe).
   → nécessaire, mais ne rattrape PAS les clones déjà faits : d'où l'étape 1.
4. Réinjecter la nouvelle clé depuis un coffre (secret Docker / Vault), à l'exécution.
```

> Pourquoi pas `git rm` en premier ? Parce que supprimer le fichier ne révoque pas la valeur : elle reste exploitable dans tout clone existant. La **révocation** est la seule action qui neutralise réellement la fuite.

**3 à 5 — `docker-compose.yml` durci + `Caddyfile`**

```yaml
# docker-compose.yml — durci
services:
  proxy:                                    # (5) terminaison TLS + HSTS, ACME auto
    image: caddy:2
    ports: ["80:80", "443:443"]             # SEULS ports publics du système
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data                     # certificats persistés (renouvellement)

  api:
    image: tribuzen-api:latest
    user: "1001:1001"                        # (4) non-root
    read_only: true                          #     FS en lecture seule
    tmpfs: ["/tmp"]                          #     seul /tmp inscriptible
    secrets: [db_password, jwt_secret]       # (3) montés dans /run/secrets/, hors env
    # PAS de `ports:` → joignable uniquement par le proxy sur le réseau interne

  db:
    image: postgres:16
    secrets: [db_password]
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password  # lit le fichier, pas une var en clair
    # (4) AUCUN `ports:` → la base n'est PAS exposée à Internet

secrets:                                     # fichiers dans ./secrets (gitignoré)
  db_password: { file: ./secrets/db_password.txt }
  jwt_secret:  { file: ./secrets/jwt_secret.txt }

volumes: { caddy_data: {} }
```

```
# Caddyfile — TLS auto (ACME/Let's Encrypt), HSTS, reverse proxy
tribuzen.app {
    encode gzip
    header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    reverse_proxy api:3000        # l'api parle en clair sur le réseau privé docker
}
# HTTP→HTTPS et le renouvellement du certificat (90 j) sont gérés par Caddy seul.
```

**6 — `logger.ts` : journal de sécurité**

```typescript
import pino from 'pino'

// redact retire les champs sensibles AVANT écriture — un log est souvent
// moins protégé que la base : on n'y met JAMAIS de secret/PII/jeton.
export const logger = pino({
  redact: {
    paths: ['req.headers.authorization', 'req.body.password', '*.token', '*.secret'],
    censor: '[REDACTED]',
  },
})

// On journalise l'ÉVÉNEMENT + contexte non sensible, jamais la valeur du secret.
export function logFailedLogin(email: string, ip: string) {
  // NB: email = donnée perso -> selon la politique PII, hacher/tronquer. On ne logge PAS le mot de passe.
  logger.warn({ action: 'failed_login', ip }, 'échec authentification')
}
export function logForbidden(userId: string, resource: string, ip: string) {
  logger.warn({ action: 'forbidden_access', userId, resource, ip }, 'accès refusé (403)')
}
export function logRateLimit(ip: string, route: string) {
  logger.warn({ action: 'rate_limit', ip, route }, 'seuil de requêtes atteint')
}
```

**À NE JAMAIS logger** (OWASP Logging Cheat Sheet) : identifiants de session, jetons d'accès, mots de passe, PII, chaînes de connexion, clés de chiffrement, données de paiement.

**8 — validation au boot (`config/env.ts`)**

```typescript
import { z } from 'zod'
import { readFileSync } from 'node:fs'

const read = (f: string) => readFileSync(`/run/secrets/${f}`, 'utf8').trim()

// Crash AU DÉMARRAGE si un secret manque ou est trop faible — jamais à chaud en prod.
export const config = z.object({
  jwtSecret: z.string().min(32),           // rejette "dev-secret-please-change"
  dbPassword: z.string().min(1),
}).parse({ jwtSecret: read('jwt_secret'), dbPassword: read('db_password') })
```

**Pourquoi ce corrigé est correct :**
- **Seuls 80/443 du proxy** sont publiés : l'api et la DB n'ont aucune surface publique (moindre privilège réseau).
- Les secrets sont **montés en fichier** (hors `environment` inspectable, hors git) et **validés au boot**.
- Le TLS est **auto-renouvelé** par Caddy — pas de certificat qui expire en silence.
- Le logger capte les événements de sécurité **utiles** avec **redaction**, sans jamais écrire de secret.
- Sur la clé Stripe fuitée, l'ordre **révoquer → ignorer → purger → réinjecter** neutralise réellement la fuite.

---

## Grille d'auto-évaluation

| Critère | Acquis si… |
|---|---|
| Secrets hors git | `.gitignore` couvre `.env`/`secrets/`/`*.pem`, `.env.example` a la **structure** sans **aucune** valeur réelle |
| Révocation d'une clé fuitée | ta procédure suit l'ordre **révoquer → ignorer → purger → réinjecter**, et tu expliques pourquoi la 1re action n'est **pas** `git rm` (la clé est déjà compromise) |
| Secrets Docker | `db_password`/`jwt_secret` sont montés via `secrets:` (fichier gitignoré) et lus dans `/run/secrets/`, **plus** dans `environment` |
| Moindre privilège | l'api tourne en **non-root**, `read_only: true` + `tmpfs`, et la **DB n'expose plus de port** |
| TLS auto-renouvelé | reverse proxy (Caddy) termine le TLS, force HTTPS + HSTS, gère ACME seul ; l'api ne publie **aucun** port |
| Surface d'attaque | après durcissement, seuls **80/443 du proxy** sont publiés, personne ne tourne en root, les secrets ne sont pas lisibles hors conteneur |
| Journal de sécurité | `pino` avec `redact` (`authorization`, `password`, `*.token`), logge `failed_login`/`forbidden`/`rate_limit`, et tu listes ce qu'il ne faut **jamais** logger |
| Fail-fast au boot | validation (Zod) qui **crash au démarrage** si `JWT_SECRET` est absent, plutôt que de tourner sans secret |

**Seuil :** « Acquis » sur secrets hors git, révocation d'une clé fuitée et moindre privilège du compose — les portes qui, ouvertes, exposent toute l'infra.

---

## Coach — conduite de session

- **Attaque la clé fuitée d'abord, pas le compose.** La `STRIPE_SECRET_KEY` committée est déjà compromise. Question d'ouverture : « elle est dans l'historique git — quelle est ta **première** action ? ». S'il répond `git rm`/purge, arrête : la clé est déjà dehors, on **révoque** avant tout.
- **Piège à débusquer #1 — « je purge l'historique et c'est réglé » :** purger `.env` de l'historique **ne dé-compromet pas** la clé (elle a pu être aspirée). L'ordre correct est révoquer → ignorer → purger → réinjecter une clé neuve.
- **Piège à débusquer #2 — secrets en `environment` :** s'il déplace les secrets mais les garde dans `environment:`, rappelle qu'ils fuient dans `docker inspect` et les logs. Le montage **fichier** (`/run/secrets/`) est le but.
- **Piège à débusquer #3 — DB encore exposée :** le réflexe « je publie 5432 pour me connecter avec mon client SQL » rouvre la base au monde. La DB ne doit être joignable **que** par l'api, via le réseau interne.
- **Piège à débusquer #4 — log qui fuite :** s'il logge le body ou l'`Authorization` « pour debugger », c'est le secret dans les logs. Fais-lui nommer la liste `redact` **et** ce qu'on ne logge jamais (mots de passe, tokens, PII de mineurs).
- **Ancrage TribuZen :** cette infra sert les **données de familles et de mineurs**. Une DB exposée ou une clé Stripe live fuitée = incident réel (RGPD, fraude). Le durcissement ferme des portes concrètes.
- **Si silence / blocage :** fais-lui faire le tour final « quels ports sont publiés ? qui tourne en root ? qui lit les secrets ? » sur le compose de départ — l'inventaire des trous cadre naturellement le travail à faire.

---

## Variante J+30 (fading)

**Même objectif, contraintes ajoutées — reproduis de mémoire, en 30 minutes, sans rouvrir ce corrigé :**

1. Remplace les secrets fichiers par une lecture depuis **HashiCorp Vault** (`node-vault`) qui renvoie des **credentials DB dynamiques** (à bail court) — explique en 2 lignes ce que ça apporte vs un fichier statique (rotation + moindre privilège).
2. Ajoute une **barrière CI** : un workflow GitHub Actions qui fait échouer le build si `gitleaks` détecte un secret dans l'historique.
3. Ajoute un **check d'expiration TLS** (script `tls.connect`) qui alerte si le certificat expire dans moins de 30 jours.

**Critère de réussite :** aucun secret en clair dans un fichier versionné, la CI bloque un secret committé, et tu sais expliquer à l'oral pourquoi révoquer prime sur purger.

---

## Application TribuZen

Dans le repo `smaurier/tribuzen`, cette config vit ici :

```
tribuzen/
  .gitignore              ← .env, secrets/, *.pem
  .env.example            ← structure committée
  docker-compose.yml      ← non-root, secrets montés, DB non exposée, proxy TLS
  Caddyfile               ← TLS auto (ACME) + HSTS + reverse proxy
  secrets/                ← db_password, jwt_secret (gitignoré)
  INCIDENT.md             ← procédure de révocation d'un secret fuité
  .github/workflows/
    secret-scan.yml       ← gitleaks en CI
  tribuzen-api/src/
    config/env.ts         ← validation Zod des secrets au boot
    common/logger.ts      ← pino + redaction, événements de sécurité
```

**Différences par rapport au lab :**
- En prod cloud, les secrets Docker/fichiers deviennent AWS Secrets Manager / Vault avec rotation managée — **cours 12** (mêmes principes, API différente).
- Le journal de sécurité alimente un agrégateur centralisé (Loki/ELK) avec alerting temps réel sur les pics d'échecs de login — utile pour repérer un accès anormal aux données familles.

**Commit cible :**
```
chore(infra): durcissement — secrets hors git, TLS auto, DB non exposée, journal de sécurité
```
