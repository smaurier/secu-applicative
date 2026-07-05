---
titre: Sécurité de l'infrastructure applicative — secrets, TLS, durcissement, logging
cours: 14-securite-applicative
notions: ["gestion des secrets", "jamais de secret en git", "variables d'env vs coffre-fort (Vault)", "rotation & expiration des secrets", "détection de secrets fuités (shift-left)", "TLS & certificats (Let's Encrypt, ACME)", "durcissement serveur (hardening)", "principe du moindre privilège en infra", "WAF (survol)", "logging de sécurité (OWASP)", "monitoring & alerting", "defense in depth infra"]
outcomes:
  - "sait sortir les secrets de TribuZen du dépôt git (gitignore, .env.example, purge d'historique) et expliquer pourquoi une variable d'env n'est pas un coffre-fort"
  - "sait raisonner sur le cycle de vie d'un secret — stockage centralisé, rotation, expiration, moindre privilège — et détecter une fuite avant le déploiement"
  - "sait configurer un TLS moderne (protocoles, HSTS, certificat ACME auto-renouvelé) derrière un reverse proxy et surveiller l'expiration"
  - "sait choisir quels événements de sécurité journaliser, lesquels EXCLURE des logs, et protéger le journal (OWASP Logging Cheat Sheet)"
  - "sait situer defense in depth au niveau infra et distinguer ce qui relève de ce cours de ce qui est déféré au cloud (cours 12)"
prerequis:
  - "Introduction sécurité — modèle de menace, CIA, defense in depth (module 00)"
  - "Cryptographie — hachage vs chiffrement, TLS, gestion de clés (module 05)"
  - "Headers de sécurité — HSTS, cookies Secure (module 06)"
  - "Supply chain — dépendances, CI, détection (module 09)"
next: 11-audit-pentest
libs: []
tribuzen: infrastructure TribuZen — secrets applicatifs (DB, JWT, clés tierces), TLS du back-office, journal de sécurité des accès familles
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Sécurité de l'infrastructure applicative — secrets, TLS, durcissement, logging

> **Outcomes — tu sauras FAIRE :** sortir les secrets de TribuZen de git et raisonner sur leur cycle de vie, configurer un TLS moderne auto-renouvelé, appliquer le moindre privilège en infra, et journaliser les événements de sécurité sans fuiter de données — le tout en couches (defense in depth).
> **Difficulté :** :star::star::star:
>
> **Angle : DÉFENSIF.** On durcit l'infra qui héberge TON app. Aucune technique offensive : ici on ferme des portes, on ne les force pas.
>
> **Portée :** ce module couvre la sécurité d'infra **applicative** — celle que TOI, dev, tu maîtrises : où vivent les secrets, comment le TLS est servi, quel privilège tourne le process, quoi journaliser. Le **cloud en profondeur** (AWS KMS, Secrets Manager managé, WAF géré, IAM détaillé, VPC) est le **cours 12**. La sécurité **architecturale** (zero-trust, segmentation, threat modeling système) est le **cours 13 module 20**. Ici : les **principes** + les gestes concrets que tu poses dans un dépôt et un `docker-compose`.

## 1. Cas concret d'abord

Tu reprends l'infra de TribuZen. Le back-office héberge des **données de mineurs** (activités, présences, contacts des familles) — l'enjeu le plus sensible de l'app. Un collègue a livré ce `docker-compose.yml` et ce `.env`. « Ça tourne en prod ».

```yaml
# docker-compose.yml — AVANT durcissement. NE PAS déployer.
services:
  api:
    image: tribuzen-api:latest
    user: root                                   # (1)
    environment:
      DATABASE_URL: postgres://admin:S3cret@db:5432/tribuzen  # (2)
      JWT_SECRET: dev-secret-please-change        # (2)
    ports:
      - "3000:3000"                              # (3) exposé en clair sur Internet
  db:
    image: postgres:16
    ports:
      - "5432:5432"                              # (4) base joignable depuis l'extérieur
```

```bash
# .env — committé dans le dépôt, visible dans l'historique git  (5)
STRIPE_SECRET_KEY=sk_live_51H...
SENTRY_DSN=https://abc@o123.ingest.sentry.io/456
```

**Cinq trous que ce module va boucher :**

1. **Process en root** — une faille applicative devient une prise de contrôle de l'hôte. Le principe du **moindre privilège** impose un utilisateur non-root.
2. **Secrets en clair dans l'environnement du compose** — lisibles par `docker inspect`, présents dans le fichier versionné, jamais rotés.
3. **Trafic en clair** — le port applicatif est exposé sans TLS ; les identifiants transitent en clair. Il faut un reverse proxy TLS devant.
4. **Base joignable depuis Internet** — la DB ne doit être accessible **que** depuis l'app (moindre privilège réseau).
5. **`.env` dans git** — le pire : `sk_live_...` est une clé de production, désormais dans l'historique **pour toujours** tant qu'on ne purge pas. Il faut la **révoquer**, pas juste la supprimer.

À la fin du module : secrets sortis de git et injectés depuis un coffre, process non-root, TLS auto-renouvelé, réseau segmenté, et un journal de sécurité qui repère les abus sans fuiter. C'est le fil rouge du lab.

---

## 2. Théorie complète, concise

### 2.1 Defense in depth au niveau infra (cadrage)

Aucune couche n'est fiable seule. On **empile** les défenses pour qu'une faille unique ne soit jamais fatale :

```
Internet
  │  TLS (chiffrement du transport)
  ▼
[ Reverse proxy / WAF ]   ← filtrage, terminaison TLS, rate limit
  │  réseau privé
  ▼
[ App non-root ]          ← moindre privilège process, secrets injectés à l'exécution
  │  réseau privé, credentials à durée de vie limitée
  ▼
[ Base de données ]       ← joignable UNIQUEMENT depuis l'app, chiffrée au repos
```

Chaque flèche est une frontière de confiance. Le **moindre privilège** est le fil conducteur : chaque composant reçoit le minimum de droits (réseau, système, accès aux secrets) pour faire son travail — rien de plus.

### 2.2 Gestion des secrets : le cycle de vie

Un **secret** = toute valeur qui, connue d'un tiers, casse une garantie de sécurité : mot de passe de base, `JWT_SECRET`, clé d'API tierce (Stripe, Sentry), clé de chiffrement, certificat privé. OWASP *Secrets Management Cheat Sheet* (vérifié 2026-07) structure leur gestion :

- **Ne jamais coder en dur** un secret dans le source — première règle, non négociable.
- **Centraliser et standardiser** (§ *Centralize and Standardize*) : une solution dédiée (HashiCorp Vault, cloud key vault) plutôt que des secrets éparpillés fichier par fichier.
- **Moindre privilège** (§ *Access Control*) : « les ingénieurs ne devraient pas avoir accès à **tous** les secrets » — chaque service/rôle n'accède qu'aux siens.
- **Automatiser** (§ *Automate Secrets Management*) : l'injection manuelle multiplie les fuites et l'erreur humaine ; préférer pipelines et **secrets dynamiques** (générés à la demande, à durée de vie courte).
- **Rotation** (§ *Rotation*) : « faire tourner régulièrement les secrets pour qu'un identifiant volé ne fonctionne qu'un court instant ».
- **Expiration** (§ *Expiration*) : un secret expire après une période définie ; l'app vérifie qu'il est encore actif avant usage.

> **Point de vigilance OWASP.** La cheat sheet **déconseille** de traiter les variables d'environnement comme un coffre-fort : elles fuient via `docker inspect`, les dumps de crash, les logs de process, les sous-process enfants. Une **variable d'env n'est pas un secret manager** — c'est au mieux un canal d'injection depuis un vrai coffre. Cf. §2.4.

### 2.3 Jamais de secret dans git

Git **n'oublie rien** : un secret committé reste dans l'historique même après suppression. La bonne posture, en couches :

```bash
# .gitignore — dès la première ligne du projet
.env
.env.*.local
*.pem
*.key
secrets/
```

```bash
# .env.example — CELUI-CI est committé : structure sans valeurs réelles
DATABASE_URL=postgres://user:password@localhost:5432/tribuzen
JWT_SECRET=change-me-32-chars-minimum
STRIPE_SECRET_KEY=sk_test_xxx
```

Si un secret **a déjà été committé** (cas du §1), la suppression du fichier ne suffit pas :

1. **Révoquer / faire tourner** la valeur immédiatement — considère-la compromise (OWASP § *Remediation* : « révocation immédiate, rotation rapide, suppression de l'historique »).
2. **Purger l'historique** (`git filter-repo`, BFG) et forcer le repush — mais un dépôt public a peut-être déjà été cloné : la révocation prime toujours sur la purge.

### 2.4 Injecter les secrets à l'exécution (Vault, secrets Docker)

Le secret vit dans un **coffre**, pas dans le dépôt ni dans l'image. Deux niveaux courants :

**Docker/Compose secrets** — montés en fichier dans `/run/secrets/`, hors de l'environnement inspectable :

```yaml
services:
  api:
    image: tribuzen-api:latest
    secrets: [db_password, jwt_secret]     # montés dans /run/secrets/
secrets:
  db_password:
    file: ./secrets/db_password.txt        # ./secrets est gitignore
  jwt_secret:
    file: ./secrets/jwt_secret.txt
```

```typescript
import { readFileSync } from 'node:fs'

// Lire le secret depuis le fichier monté — jamais depuis process.env pour un secret réel.
function readSecret(name: string): string {
  return readFileSync(`/run/secrets/${name}`, 'utf8').trim()
}
const dbPassword = readSecret('db_password')
```

**Coffre-fort (Vault)** — centralise, audite, et peut générer des **credentials dynamiques** à bail (lease) court :

```typescript
import Vault from 'node-vault'

const vault = Vault({ endpoint: process.env.VAULT_ADDR, token: process.env.VAULT_TOKEN })

// Vault renvoie des identifiants DB temporaires qui expirent seuls (moindre privilège + rotation).
async function getDbCredentials() {
  const { data } = await vault.read('database/creds/tribuzen-api')
  return { username: data.username, password: data.password }
}
```

> **Déféré → cours 12.** AWS Secrets Manager, KMS, l'intégration IAM et la rotation managée sont du **cloud spécifique** : mêmes principes (centralisation, rotation, moindre privilège), API différente. Ici on retient le **modèle**, pas le SDK d'un fournisseur.

**Valider les secrets au démarrage** — l'app doit refuser de booter si un secret manque ou est trop faible :

```typescript
import { z } from 'zod'

const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),   // rejette "dev-secret" du §1
  NODE_ENV: z.enum(['development', 'production', 'test']),
})
export const config = envSchema.parse(process.env)   // throw = crash au boot, pas en prod à chaud
```

### 2.5 Détection de secrets fuités (shift-left)

On repère la fuite **avant** qu'elle parte (OWASP § *Detection*, approche *shift-left*) :

- **Pre-commit / CI** : un scanner (`detect-secrets`, `gitleaks`, `trufflehog`) bloque le commit ou le build si un pattern de secret apparaît.
- Sur fuite avérée → §2.3 : **révoquer d'abord**, purger ensuite.

```yaml
# .github/workflows/secret-scan.yml — barrière CI
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }        # historique complet pour scanner les commits passés
      - uses: gitleaks/gitleaks-action@v2
```

### 2.6 TLS & certificats

Tout le trafic est chiffré de bout en bout — plus jamais de HTTP en clair (rappel crypto → module 05, HSTS → module 06). Le TLS est **terminé au reverse proxy** ; l'app parle en clair sur le réseau **privé** derrière.

```nginx
server {                       # redirige tout HTTP vers HTTPS
  listen 80;
  server_name tribuzen.app;
  return 301 https://$host$request_uri;
}
server {
  listen 443 ssl;
  http2 on;
  server_name tribuzen.app;

  ssl_certificate     /etc/letsencrypt/live/tribuzen.app/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/tribuzen.app/privkey.pem;

  ssl_protocols TLSv1.2 TLSv1.3;          # TLS 1.0/1.1 désactivés (obsolètes)
  ssl_prefer_server_ciphers off;          # laisse le client choisir un cipher moderne (TLS 1.3)

  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

  location / {
    proxy_pass http://api:3000;           # clair, mais sur le réseau docker privé
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

**Certificats automatisés (ACME / Let's Encrypt)** — les certificats gratuits ACME durent 90 jours ; le renouvellement doit être **automatique** (Certbot en cron, ou un proxy comme Caddy/Traefik qui gère ACME seul). Un certificat expiré = site cassé.

**Surveiller l'expiration** — filet de sécurité si l'auto-renouvellement casse :

```typescript
import tls from 'node:tls'

function daysUntilExpiry(host: string, port = 443): Promise<number> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername: host }, () => {
      const { valid_to } = socket.getPeerCertificate()
      const days = Math.floor((new Date(valid_to).getTime() - Date.now()) / 86_400_000)
      socket.end(); resolve(days)
    })
    socket.on('error', reject)
  })
}
// Alerter sous 30 jours restants — l'auto-renew a peut-être échoué silencieusement.
```

### 2.7 Durcissement serveur (hardening) & moindre privilège

Réduire la **surface d'attaque** et le **rayon d'explosion** d'une compromission :

- **Process non-root** — l'app tourne sous un utilisateur dédié sans privilège. Une RCE ne donne pas l'hôte.
- **Image minimale** — `-slim` ou `distroless` : moins de binaires = moins de failles et pas de shell à détourner.
- **Système de fichiers en lecture seule** (`read_only: true` + `tmpfs` pour `/tmp`) — un attaquant ne peut pas déposer de payload.
- **Moindre privilège réseau** — chaque service n'ouvre que les ports strictement nécessaires ; la DB n'est joignable **que** depuis l'app (pas de `ports:` publiés pour la base).
- **Pas de secrets ni de `.git` dans l'image** (`.dockerignore`).

```dockerfile
# Runtime durci (extrait) — utilisateur dédié, non-root
RUN addgroup -S app && adduser -S app -G app
USER app                       # tout ce qui suit tourne sans privilège
EXPOSE 3000
CMD ["node", "dist/main.js"]
```

```yaml
# compose — moindre privilège : la DB n'expose AUCUN port public
services:
  api:
    user: "1001:1001"
    read_only: true
    tmpfs: ["/tmp"]
  db:
    image: postgres:16          # pas de `ports:` → joignable seulement sur le réseau interne
```

### 2.8 WAF (survol)

Un **WAF** (Web Application Firewall) inspecte le trafic HTTP en amont de l'app et bloque des patterns d'attaque connus (injections, scans, mauvais bots), applique du rate limiting et filtrage géo/IP. C'est une **couche de plus** (defense in depth), **jamais un substitut** au code sécurisé : un WAF se contourne, il ne corrige pas la vuln. En applicatif : ModSecurity (règles OWASP CRS) devant Nginx, ou l'option WAF d'un proxy.

> **Déféré → cours 12.** AWS WAF, Cloudflare et les WAF managés (règles, ACL, intégration CDN) relèvent du cloud. Retiens ici le **rôle** du WAF et sa limite, pas la config d'un fournisseur.

### 2.9 Logging & monitoring de sécurité

Sans journal, une intrusion est **invisible**. OWASP *Logging Cheat Sheet* (vérifié 2026-07) cadre trois questions : quoi journaliser, quoi **exclure**, comment protéger.

**Événements à journaliser** (§ *Which events to log*) :

| Événement | Pourquoi |
|---|---|
| Échecs de validation d'entrée/sortie | tentative d'injection possible |
| Succès **et** échecs d'authentification | audit trail + détection brute-force |
| Échecs d'autorisation (contrôle d'accès) | tentative d'escalade de privilège |
| Échecs de gestion de session (ex. modif d'un cookie de session) | vol/forge de session |
| Erreurs applicatives et système | fiabilité + signal d'attaque |
| Fonctionnalités à haut risque (admin users, privilèges système, accès données sensibles, crypto, import/export) | traçabilité des actions critiques |

**Données à EXCLURE du journal** (§ *Data to exclude*) — **ne jamais logger** : identifiants de session, jetons d'accès, données personnelles/PII, mots de passe, chaînes de connexion à la base, clés de chiffrement et secrets, données de carte de paiement. Un log est souvent moins protégé que la base : y écrire un secret, c'est le fuiter.

```typescript
import pino from 'pino'

// La redaction retire les champs sensibles AVANT écriture — ceinture et bretelles.
const logger = pino({
  redact: { paths: ['req.headers.authorization', 'req.body.password', '*.token'], censor: '[REDACTED]' },
})

// On journalise l'ÉVÉNEMENT et son contexte non sensible, jamais le secret lui-même.
logger.warn({ userId, action: 'failed_login', ip: req.ip }, 'échec authentification')
```

**Protéger le journal** (§ *Protection*) : détection d'altération (tamper), stockage en **lecture seule** au plus tôt, accès restreint et audité, transmission chiffrée sur réseau non fiable.

**Monitorer** (§ *Monitoring of events*) : centraliser (agrégateur type Loki/ELK), **alerter en temps réel** sur les événements graves (pic d'échecs de login, 403 en série, rate limit atteint). Un log que personne ne lit ne défend rien.

---

## 3. Worked examples

### Exemple 1 — Sortir un secret déjà committé (le cas du §1)

`.env` avec `STRIPE_SECRET_KEY=sk_live_...` a été poussé. Procédure défensive, dans l'ordre :

```bash
# 1. RÉVOQUER d'abord — la clé est compromise dès qu'elle a touché l'historique.
#    (dashboard Stripe → roll/revoke). C'est l'étape qui compte vraiment.

# 2. Empêcher la récidive : ignorer le fichier et publier un exemple sans valeurs.
#    .gitignore : .env      |   commit .env.example (placeholders uniquement)

# 3. Purger l'historique (l'ancienne valeur reste sinon dans chaque clone/backup).
git filter-repo --path .env --invert-paths     # réécrit l'historique
git push --force-with-lease origin main         # concertation équipe requise

# 4. Rebrancher : la vraie clé vit désormais dans un coffre (secret Docker / Vault),
#    injectée à l'exécution — cf. §2.4.
```

**L'ordre est le message** : révoquer > ignorer > purger > réinjecter. Purger sans révoquer laisse la clé exploitable dans n'importe quel clone déjà fait.

### Exemple 2 — Durcir le compose du §1

```yaml
# docker-compose.yml — APRÈS durcissement
services:
  proxy:                                  # (3) terminaison TLS + HSTS devant l'app
    image: caddy:2                        #     Caddy gère ACME/Let's Encrypt tout seul
    ports: ["80:80", "443:443"]
    volumes: ["./Caddyfile:/etc/caddy/Caddyfile:ro", "caddy_data:/data"]

  api:
    image: tribuzen-api:latest
    user: "1001:1001"                     # (1) non-root
    read_only: true                       #     FS en lecture seule
    tmpfs: ["/tmp"]
    secrets: [db_password, jwt_secret]    # (2) secrets montés en fichier, hors env
    # PAS de `ports:` publié — joignable seulement par le proxy sur le réseau interne

  db:
    image: postgres:16
    # (4) AUCUN `ports:` → la base n'est PAS joignable depuis Internet
    secrets: [db_password]
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password

secrets:                                  # (5) fichiers dans ./secrets (gitignore)
  db_password: { file: ./secrets/db_password.txt }
  jwt_secret:  { file: ./secrets/jwt_secret.txt }

volumes: { caddy_data: {} }
```

Les cinq trous du §1 sont bouchés : non-root, secrets hors git/hors env, TLS auto-renouvelé au proxy, DB non exposée, `.env` remplacé par des secrets montés. Chaque défense est une **couche** : même si l'une cède, les autres tiennent.

---

## 4. Pièges & misconceptions

### PIÈGE #1 — « Le secret n'est pas dans le code, il est dans une variable d'env : c'est sûr »
Une variable d'env **n'est pas un coffre-fort** (OWASP le déconseille explicitement) : elle fuit via `docker inspect`, les dumps de crash, les sous-process, les logs. Correct : la source de vérité est un **coffre** (Vault, secret Docker monté en fichier) ; l'env n'est qu'un canal d'injection au démarrage — et jamais committé.

### PIÈGE #2 — « J'ai supprimé le `.env` du repo, le secret est safe »
Faux. Git conserve tout l'historique ; le secret reste clonable. **Le supprimer ne le protège pas — il faut le RÉVOQUER.** La purge d'historique vient après, et ne rattrape pas les clones déjà faits. Révoquer d'abord, toujours.

### PIÈGE #3 — « Un WAF devant l'app, donc l'app est protégée »
Un WAF est une **couche** de defense in depth, pas un correctif. Il bloque des patterns connus mais se contourne (encodages, variantes). Il n'excuse jamais une requête non paramétrée ou une entrée non validée. Le code sécurisé reste la défense primaire.

### PIÈGE #4 — « HTTPS activé une fois = tranquille »
Les certificats ACME expirent en **90 jours**. Sans **auto-renouvellement** (Certbot cron / Caddy / Traefik) le site casse. Et sans **monitoring d'expiration**, on découvre la panne par les utilisateurs. Automatiser le renouvellement ET surveiller la date restante.

### PIÈGE #5 — « Loggons tout, on triera après »
Tout logger fait **fuiter des secrets** dans un journal souvent moins protégé que la base. OWASP interdit d'y écrire mots de passe, jetons, PII, clés, chaînes de connexion. Correct : journaliser l'**événement** et son contexte non sensible, avec **redaction** des champs sensibles avant écriture.

### PIÈGE #6 — « Le conteneur isole, tourner en root dedans est sans risque »
Un process root dans un conteneur reste root : une RCE + une évasion de conteneur = hôte compromis. **Moindre privilège** : utilisateur non-root, FS en lecture seule, image minimale. La conteneurisation réduit le rayon d'explosion, elle ne l'annule pas.

### PIÈGE #7 — « La base a un mot de passe fort, elle peut être exposée »
Exposer le port de la DB sur Internet, c'est offrir la surface d'attaque (0-day du moteur, brute-force, scan). Moindre privilège réseau : la base n'est joignable **que** depuis l'app, sur le réseau privé — aucun `ports:` publié.

---

## 5. Ancrage TribuZen

L'infra de TribuZen héberge des **données de mineurs** : le durcissement n'est pas cosmétique, c'est la condition pour manipuler ces données.

Où ça vit dans `smaurier/tribuzen` :

```
tribuzen/
  .gitignore                  ← .env, secrets/, *.pem exclus
  .env.example                ← structure committée, sans valeurs
  docker-compose.yml          ← non-root, secrets montés, DB non exposée, proxy TLS
  Caddyfile                   ← TLS auto (ACME), HSTS, reverse proxy vers l'api
  secrets/                    ← db_password, jwt_secret (gitignore, injectés à l'exécution)
  .github/workflows/
    secret-scan.yml           ← gitleaks bloque un secret committé en CI
  tribuzen-api/src/
    config/env.ts             ← validation Zod des secrets au boot (crash si manquant/faible)
    common/logger.ts          ← pino + redaction ; événements de sécurité (login, 403, rate limit)
```

Points d'ancrage concrets :
- **Secrets** : `DATABASE_URL`, `JWT_SECRET`, clés Stripe/Sentry hors git, montés depuis `secrets/`, validés au démarrage.
- **TLS** : Caddy termine le TLS et auto-renouvelle ; l'api ne publie aucun port, la DB non plus.
- **Journal de sécurité** : chaque échec de login, 403 sur une famille, ou rate limit atteint est loggé (contexte non sensible, redaction) et alertable — utile pour repérer un accès anormal aux données familles.
- **Moindre privilège** : api non-root, FS read-only, DB joignable seulement par l'api.
- **Cloud managé** (KMS, Secrets Manager, WAF géré) → **cours 12**, quand TribuZen passe sur une infra cloud.

---

## 6. Points clés

1. **Defense in depth infra** : on empile TLS, WAF, process non-root, réseau segmenté — aucune couche n'est fiable seule ; le fil conducteur est le **moindre privilège**.
2. Un **secret** ne vit ni dans le code ni dans git : coffre centralisé, **rotation**, **expiration**, accès au moindre privilège (OWASP Secrets Management).
3. Une **variable d'env n'est pas un coffre-fort** — elle fuit (`docker inspect`, dumps, logs) ; c'est un canal d'injection depuis un vrai coffre, jamais committé.
4. Secret déjà committé → **RÉVOQUER d'abord**, gitignore + `.env.example`, purger l'historique ensuite ; la révocation prime toujours.
5. **Détecter avant de déployer** (shift-left) : gitleaks/detect-secrets en pre-commit et CI.
6. **TLS** terminé au reverse proxy, protocoles modernes (TLS 1.2/1.3) + HSTS, certificat ACME **auto-renouvelé** (90 j) et **expiration surveillée**.
7. **Durcissement** : image minimale, utilisateur non-root, FS read-only, DB non exposée (joignable seulement depuis l'app).
8. Un **WAF** est une couche de plus, jamais un substitut au code sécurisé.
9. **Logger** les événements de sécurité (auth, autorisation, session, haut risque) ; **EXCLURE** secrets/PII/jetons ; protéger le journal (lecture seule, accès audité) et **alerter** en temps réel.

---

## 7. Seeds Anki

```
Pourquoi une variable d'environnement n'est-elle pas un coffre-fort à secrets ?|OWASP la déconseille : elle fuit via docker inspect, les dumps de crash, les logs de process et les sous-process. C'est au mieux un canal d'injection depuis un vrai coffre (Vault, secret Docker monté en fichier), jamais la source de vérité, jamais committée.
Un secret a été committé dans git. Quelle est la PREMIÈRE action ?|Le RÉVOQUER / faire tourner immédiatement — il est compromis dès qu'il a touché l'historique. Supprimer le fichier ou purger l'historique ne suffit pas (clones/backups existants). Ordre : révoquer > gitignore + .env.example > purger l'historique > réinjecter depuis un coffre.
Cite trois pratiques du cycle de vie d'un secret (OWASP Secrets Management).|Centraliser dans une solution dédiée (Vault/key vault), moindre privilège d'accès (personne n'a tous les secrets), rotation régulière, expiration à durée définie, automatisation (secrets dynamiques à bail court). Ne jamais coder en dur.
Que signifie le moindre privilège au niveau infra ? Donne deux exemples.|Chaque composant reçoit le minimum de droits pour fonctionner. Ex : process app en utilisateur non-root (une RCE ne donne pas l'hôte) ; base de données joignable UNIQUEMENT depuis l'app, aucun port publié sur Internet.
Combien de temps dure un certificat ACME/Let's Encrypt et quelle est la conséquence ?|90 jours. Le renouvellement doit être AUTOMATIQUE (Certbot cron, Caddy, Traefik) sinon le site casse, et l'expiration doit être surveillée (alerte < 30 j) au cas où l'auto-renew échoue silencieusement.
Un WAF suffit-il à sécuriser une application ?|Non. C'est une couche de defense in depth (bloque des patterns connus, rate limit) mais il se contourne et ne corrige pas la vuln. Le code sécurisé (validation, requêtes paramétrées) reste la défense primaire.
Quels événements journaliser pour la sécurité (OWASP Logging) ?|Échecs de validation d'entrée/sortie, succès ET échecs d'authentification, échecs d'autorisation, échecs de gestion de session, erreurs applicatives/système, usage de fonctions à haut risque (admin, privilèges système, accès données sensibles, crypto, import/export).
Que ne faut-il JAMAIS écrire dans les logs ?|Identifiants de session, jetons d'accès, mots de passe, PII/données personnelles, chaînes de connexion à la base, clés de chiffrement et secrets, données de carte de paiement. Un log est souvent moins protégé que la base — utiliser la redaction avant écriture.
Pourquoi ne pas exposer le port de la base de données sur Internet malgré un mot de passe fort ?|Ça offre la surface d'attaque (0-day du moteur, brute-force, scan) indépendamment du mot de passe. Moindre privilège réseau : la base ne doit être joignable que depuis l'app sur le réseau privé, aucun ports: publié.
```

---

## Pont vers le lab

> Lab associé : `labs/lab-10-infrastructure/README.md`. Exercice **défensif** : durcir l'infra de TribuZen — sortir les secrets de git (gitignore, `.env.example`, procédure de révocation), configurer un TLS auto-renouvelé au reverse proxy, et poser un journal de sécurité qui logge les bons événements sans fuiter. Vrai `docker-compose` + config, pas de harnais simulé. Corrigé commenté + variante J+30.
