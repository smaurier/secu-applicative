# Module 10 — Sécurité de l'Infrastructure

## Objectifs pédagogiques

- Sécuriser les conteneurs Docker (images, utilisateurs, secrets)
- Gérer les secrets applicatifs sans les exposer
- Comprendre les bases de la sécurité réseau
- Mettre en place HTTPS partout avec des certificats automatisés
- Configurer le logging et le monitoring de sécurité
- Établir une stratégie de backup et de disaster recovery

---

## 1. Sécurité Docker

### 1.1 Images minimales

Plus une image est petite, plus la surface d'attaque est réduite.

| Image | Taille | Shell | Package Manager | Recommandation |
|---|---|---|---|---|
| `node:20` | ~1 GB | ✅ | ✅ | Développement seulement |
| `node:20-slim` | ~200 MB | ✅ | ✅ | Acceptable |
| `node:20-alpine` | ~130 MB | ✅ | apk | Bon compromis |
| `gcr.io/distroless/nodejs20` | ~120 MB | ❌ | ❌ | Production idéale |

### 1.2 Multi-stage builds

Séparez le build de l'exécution pour ne garder que le strict nécessaire :

```dockerfile
# Stage 1 : Build
FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

# Stage 2 : Runtime
FROM node:20-alpine AS runtime

# Utilisateur non-root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app
COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/package.json ./

USER appuser

EXPOSE 3000
CMD ["node", "dist/main.js"]
```

### 1.3 Non-root user

**Ne jamais exécuter une application en tant que root** dans un conteneur :

```dockerfile
# Créer un utilisateur dédié
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Changer les permissions des fichiers
COPY --chown=appuser:appgroup . .

# Basculer vers cet utilisateur
USER appuser
```

### 1.4 Scanning d'images

```bash
# Trivy — scanner open source
trivy image my-app:latest

# Résultat exemple
# my-app:latest
# Total: 3 (HIGH: 2, CRITICAL: 1)
#
# ┌──────────────┬────────────────┬──────────┬───────────────────┐
# │   Library    │ Vulnerability  │ Severity │  Fixed Version    │
# ├──────────────┼────────────────┼──────────┼───────────────────┤
# │ openssl      │ CVE-2024-XXXX  │ CRITICAL │ 3.1.5             │
# │ curl         │ CVE-2024-YYYY  │ HIGH     │ 8.6.0             │
# └──────────────┴────────────────┴──────────┴───────────────────┘
```

Intégration en CI :

```yaml
# .github/workflows/docker-security.yml
name: Docker Security Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t my-app:${{ github.sha }} .
      - name: Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: my-app:${{ github.sha }}
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
```

### 1.5 Docker secrets

Pour Docker Swarm ou Compose, utilisez les secrets natifs plutôt que les variables d'environnement :

```yaml
# docker-compose.yml
services:
  api:
    image: my-app:latest
    secrets:
      - db_password
      - jwt_secret

secrets:
  db_password:
    file: ./secrets/db_password.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt
```

```typescript
import { readFileSync } from 'fs';

// Les secrets sont montés dans /run/secrets/
function getSecret(name: string): string {
  return readFileSync(`/run/secrets/${name}`, 'utf8').trim();
}

const dbPassword = getSecret('db_password');
```

### 1.6 Read-only filesystem

Empêcher l'écriture dans le conteneur réduit l'impact d'une compromission :

```yaml
services:
  api:
    image: my-app:latest
    read_only: true
    tmpfs:
      - /tmp  # Seul /tmp est inscriptible
```

---

## 2. Gestion des secrets

### 2.1 Ne JAMAIS committer de secrets

```bash
# .gitignore — à configurer dès le début du projet
.env
.env.local
.env.*.local
*.pem
*.key
secrets/
```

Vérifiez qu'aucun secret n'est dans l'historique Git :

```bash
# Rechercher des patterns de secrets dans l'historique
git log --all -p | grep -iE '(password|secret|api_key|token)\s*=' | head -20
```

### 2.2 .env et bonnes pratiques

```bash
# .env.example — committez ce fichier (sans les vraies valeurs)
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
JWT_SECRET=your-secret-here
API_KEY=your-api-key-here

# .env — NE JAMAIS COMMITTER
DATABASE_URL=postgresql://admin:s3cur3P@ss@prod-db:5432/myapp
JWT_SECRET=a1b2c3d4e5f6...
```

```typescript
import { z } from 'zod';

// Valider les variables d'environnement au démarrage
const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  NODE_ENV: z.enum(['development', 'production', 'test']),
  PORT: z.coerce.number().default(3000),
});

const env = envSchema.parse(process.env);
export default env;
```

### 2.3 HashiCorp Vault

Vault centralise la gestion des secrets avec rotation, audit, et contrôle d'accès :

```typescript
import Vault from 'node-vault';

const vault = Vault({
  apiVersion: 'v1',
  endpoint: process.env.VAULT_ADDR,
  token: process.env.VAULT_TOKEN,
});

async function getDbCredentials(): Promise<{ username: string; password: string }> {
  // Vault génère des credentials temporaires
  const result = await vault.read('database/creds/my-app-role');
  return {
    username: result.data.username,
    password: result.data.password,
  };
  // Ces credentials expireront automatiquement selon le lease
}
```

### 2.4 AWS Secrets Manager

```typescript
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

const client = new SecretsManagerClient({ region: 'eu-west-1' });

async function getSecret(secretName: string): Promise<Record<string, string>> {
  const command = new GetSecretValueCommand({ SecretId: secretName });
  const response = await client.send(command);

  if (!response.SecretString) {
    throw new Error(`Secret ${secretName} is empty`);
  }

  return JSON.parse(response.SecretString);
}

// Utilisation
const dbCreds = await getSecret('prod/myapp/database');
```

### 2.5 Rotation automatique

Les secrets doivent être **rotés régulièrement** :

- Mots de passe de base de données : tous les 30-90 jours
- Clés API : tous les 90 jours
- Clés JWT : rotation progressive avec période de chevauchement
- Certificats TLS : automatique avec Let's Encrypt (90 jours)

### 2.6 Détection de secrets leakés

```bash
# GitGuardian — scanne les commits pour les secrets
# Intégration CI
# ggshield secret scan ci

# truffleHog — recherche dans l'historique Git complet
trufflehog git file://. --only-verified
```

---

## 3. Sécurité réseau

### 3.1 Firewall et Security Groups

Principe du **moindre privilège réseau** :

```
┌─────────────────────────────────────────────┐
│                 Internet                     │
└────────────────────┬────────────────────────┘
                     │ Port 443 (HTTPS)
              ┌──────┴──────┐
              │  Load       │
              │  Balancer   │
              └──────┬──────┘
                     │ Port 3000
              ┌──────┴──────┐
              │  App Server │  Security Group: allow 3000 from LB only
              └──────┬──────┘
                     │ Port 5432
              ┌──────┴──────┐
              │  Database   │  Security Group: allow 5432 from App only
              └─────────────┘
```

### 3.2 Network segmentation

- **DMZ** : serveurs exposés à Internet (reverse proxy, CDN)
- **Application** : serveurs d'application (pas d'accès direct depuis Internet)
- **Data** : bases de données (accessibles uniquement depuis le réseau application)

### 3.3 VPN et tunnels SSH

```bash
# Tunnel SSH pour accéder à une base de données en production
# JAMAIS de base de données exposée directement à Internet
ssh -L 5432:prod-db.internal:5432 bastion.example.com
```

---

## 4. HTTPS partout

### 4.1 Reverse proxy avec Nginx

```nginx
server {
    listen 80;
    server_name example.com;
    # Rediriger tout le trafic HTTP vers HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # Configuration TLS sécurisée
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    location / {
        proxy_pass http://app:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 4.2 Let's Encrypt avec Certbot

```bash
# Installation et renouvellement automatique
certbot certonly --nginx -d example.com -d www.example.com

# Renouvellement automatique (cron)
# 0 0,12 * * * certbot renew --quiet
```

### 4.3 Avec Traefik (Docker)

```yaml
# docker-compose.yml
services:
  traefik:
    image: traefik:v3
    command:
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - letsencrypt:/letsencrypt

  api:
    image: my-app:latest
    labels:
      - "traefik.http.routers.api.rule=Host(`api.example.com`)"
      - "traefik.http.routers.api.tls.certresolver=letsencrypt"

volumes:
  letsencrypt:
```

### 4.4 Certificate monitoring

```typescript
import tls from 'tls';

function checkCertificateExpiry(hostname: string, port = 443): Promise<number> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: hostname, port, servername: hostname }, () => {
      const cert = socket.getPeerCertificate();
      const expiryDate = new Date(cert.valid_to);
      const daysUntilExpiry = Math.floor(
        (expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
      );
      socket.end();
      resolve(daysUntilExpiry);
    });
    socket.on('error', reject);
  });
}

// Alerter si le certificat expire dans moins de 30 jours
const days = await checkCertificateExpiry('example.com');
if (days < 30) {
  console.warn(`⚠️ Certificat expire dans ${days} jours !`);
}
```

---

## 5. Logging et monitoring de sécurité

### 5.1 Structured logging

```typescript
import pino from 'pino';

const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  redact: {
    paths: ['req.headers.authorization', 'req.body.password', 'req.body.creditCard'],
    censor: '[REDACTED]',
  },
  formatters: {
    level: (label) => ({ level: label }),
  },
});

// Utilisation
logger.info({ userId: user.id, action: 'login', ip: req.ip }, 'User logged in');
logger.warn({ userId: user.id, action: 'failed_login', ip: req.ip }, 'Failed login attempt');
logger.error({ error: err.message, stack: err.stack }, 'Unhandled error');
```

### 5.2 Ne pas logger les données sensibles

```typescript
// ❌ MAUVAIS — données sensibles dans les logs
logger.info(`User login: email=${email}, password=${password}`);
logger.info(`Payment: card=${cardNumber}, amount=${amount}`);

// ✅ BON — données masquées
logger.info({ userId, action: 'login' }, 'Login successful');
logger.info({ transactionId, amount }, 'Payment processed');
```

### 5.3 Événements de sécurité à logger

| Événement | Niveau | Objectif |
|---|---|---|
| Login réussi | INFO | Audit trail |
| Login échoué | WARN | Détection de brute force |
| Token invalide | WARN | Détection de compromission |
| Accès non autorisé (403) | WARN | Tentative d'escalade de privilèges |
| Rate limit atteint | WARN | Détection d'abus |
| Erreur 500 | ERROR | Problème applicatif |
| Input validation failure | WARN | Tentative d'injection possible |

### 5.4 Centralized logging

```yaml
# docker-compose.yml avec Loki + Grafana
services:
  loki:
    image: grafana/loki:latest
    ports:
      - "3100:3100"

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}

  api:
    image: my-app:latest
    logging:
      driver: loki
      options:
        loki-url: "http://loki:3100/loki/api/v1/push"
        loki-batch-size: "400"
```

---

## 6. Backups et disaster recovery

### 6.1 Stratégie 3-2-1

- **3** copies de vos données
- **2** supports de stockage différents
- **1** copie hors site (off-site)

### 6.2 Backups chiffrés

```bash
# Backup PostgreSQL chiffré
pg_dump -h localhost -U admin mydb | \
  gpg --symmetric --cipher-algo AES256 --output backup-$(date +%Y%m%d).sql.gpg

# Restauration
gpg --decrypt backup-20260101.sql.gpg | psql -h localhost -U admin mydb
```

### 6.3 Script de backup automatisé

```typescript
import { execSync } from 'child_process';

function performBackup(): void {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `backup-${timestamp}.sql.gpg`;

  // Dump + chiffrement
  execSync(
    `pg_dump -h ${process.env.DB_HOST} -U ${process.env.DB_USER} ${process.env.DB_NAME} | ` +
    `gpg --batch --symmetric --passphrase-file /run/secrets/backup_passphrase --cipher-algo AES256 ` +
    `--output /backups/${filename}`
  );

  // Upload vers S3
  execSync(`aws s3 cp /backups/${filename} s3://my-backups/${filename}`);

  console.log(`Backup completed: ${filename}`);
}
```

### 6.4 Recovery testing

> **Un backup non testé n'est pas un backup.**

Planifiez des **tests de restauration réguliers** (au moins trimestriels) :

1. Restaurer le backup dans un environnement de test
2. Vérifier l'intégrité des données
3. Mesurer le **RTO** (Recovery Time Objective)
4. Documenter la procédure de récupération

---

## 7. Résumé

| Domaine | Mesure clé |
|---|---|
| Docker | Images minimales, non-root, scanning |
| Secrets | Vault/Secrets Manager, rotation, détection de leaks |
| Réseau | Segmentation, firewall, pas de DB exposée |
| HTTPS | Partout, Let's Encrypt, monitoring des certificats |
| Logging | Structuré, centralisé, sans données sensibles |
| Backups | 3-2-1, chiffrés, testés régulièrement |

---

## Exercice pratique

1. Créez un Dockerfile multi-stage avec un utilisateur non-root
2. Scannez l'image avec Trivy
3. Configurez un `.env.example` et validez les variables avec Zod
4. Mettez en place un reverse proxy Nginx avec HTTPS (Let's Encrypt)
5. Configurez le logging structuré avec Pino et la redaction des données sensibles
6. Écrivez un script de backup chiffré pour PostgreSQL

---

## Ressources

- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [Trivy Scanner](https://trivy.dev/)
- [HashiCorp Vault](https://www.vaultproject.io/)
- [Let's Encrypt](https://letsencrypt.org/)
- [Pino Logger](https://getpino.io/)
- [OWASP Docker Security Cheat Sheet](https://cheats.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
