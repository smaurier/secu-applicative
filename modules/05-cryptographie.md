# Module 5 — Cryptographie

## Objectifs pédagogiques

- Distinguer chiffrement, hashing et encodage
- Maîtriser le hashing sécurisé et l'HMAC
- Implémenter le chiffrement symétrique (AES-256-GCM) et asymétrique (RSA, ECDSA)
- Comprendre TLS 1.3 et la gestion des certificats
- Gérer les secrets de manière sécurisée
- Utiliser le module `crypto` de Node.js en pratique

---

## 1. Principes fondamentaux

### Chiffrement vs Hashing vs Encoding

| | Chiffrement | Hashing | Encoding |
|---|---|---|---|
| **Réversible** | Oui (avec la clé) | Non (one-way) | Oui (sans clé) |
| **But** | Confidentialité | Intégrité, vérification | Représentation de données |
| **Clé nécessaire** | Oui | Non | Non |
| **Exemples** | AES, RSA | SHA-256, bcrypt | Base64, UTF-8, URL encoding |
| **Use case** | Données sensibles au repos | Mots de passe, checksums | Transport de données |

```typescript
import crypto from 'node:crypto';

// ENCODING — transformation de format (pas de sécurité)
const encoded = Buffer.from('secret').toString('base64');  // "c2VjcmV0"
const decoded = Buffer.from(encoded, 'base64').toString();  // "secret"

// HASHING — empreinte irréversible
const hash = crypto.createHash('sha256').update('data').digest('hex');
// "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7"

// CHIFFREMENT — transformation réversible avec clé
// → Voir section dédiée plus bas
```

### La règle n°1 de la cryptographie

> **Ne jamais inventer sa propre cryptographie.**

Utiliser des algorithmes et bibliothèques éprouvés :
- Node.js `crypto` (wrapper autour d'OpenSSL)
- `libsodium` / `tweetnacl` pour du haut niveau
- `jose` pour JWT et JWE

---

## 2. Hashing

### 2.1 Fonctions de hashing cryptographique

```typescript
import crypto from 'node:crypto';

// SHA-256 — standard actuel
function sha256(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// SHA-3 (Keccak) — alternative à SHA-2
function sha3_256(data: string): string {
  return crypto.createHash('sha3-256').update(data).digest('hex');
}

// Hashing d'un fichier (streaming pour les gros fichiers)
import fs from 'node:fs';

async function hashFile(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

// Vérifier l'intégrité d'un téléchargement
const expectedHash = 'a1b2c3d4...'; // Hash fourni par le distributeur
const actualHash = await hashFile('./download.tar.gz');
if (actualHash !== expectedHash) {
  throw new Error('Le fichier a été altéré !');
}
```

### 2.2 Hashing de mots de passe

Les fonctions de hashing classiques (SHA-256) sont **trop rapides** pour les mots de passe. On utilise des fonctions de hashing **lentes et coûteuses** pour résister au brute force.

```typescript
// ╔══════════════════════════════════════════════════════════╗
// ║  NE JAMAIS utiliser MD5, SHA-1 ou SHA-256               ║
// ║  pour hasher des mots de passe                          ║
// ╚══════════════════════════════════════════════════════════╝

// ✅ bcrypt — standard éprouvé
import bcrypt from 'bcrypt';

const COST_FACTOR = 12;  // 2^12 itérations (~250ms)

async function hashPasswordBcrypt(password: string): Promise<string> {
  return bcrypt.hash(password, COST_FACTOR);
}

// ✅ scrypt — inclus dans Node.js nativement
async function hashPasswordScrypt(password: string): Promise<string> {
  const salt = crypto.randomBytes(16);
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, key) => {
      if (err) reject(err);
      resolve(`${salt.toString('hex')}:${key.toString('hex')}`);
    });
  });
}

// ✅ argon2id — le plus recommandé (vainqueur de PHC)
import { hash, verify, argon2id } from 'argon2';

async function hashPasswordArgon2(password: string): Promise<string> {
  return hash(password, {
    type: argon2id,
    memoryCost: 65536,  // 64 MB — résiste aux attaques GPU
    timeCost: 3,
    parallelism: 4,
  });
}
```

### Comparaison des algorithmes de hashing de mots de passe

| Algorithme | Résistance GPU | Mémoire | Standard |
|---|---|---|---|
| bcrypt | Bonne | Faible (4KB) | Très répandu |
| scrypt | Très bonne | Configurable | Crypto (Litecoin) |
| argon2id | Excellente | Configurable (64MB+) | PHC Winner, OWASP recommandé |

### 2.3 HMAC — Hash-based Message Authentication Code

HMAC combine un hash avec une **clé secrète** pour garantir à la fois l'intégrité et l'authenticité.

```typescript
import crypto from 'node:crypto';

const HMAC_SECRET = process.env.HMAC_SECRET!;

// Créer un HMAC
function createHMAC(data: string): string {
  return crypto
    .createHmac('sha256', HMAC_SECRET)
    .update(data)
    .digest('hex');
}

// Vérifier un HMAC de manière timing-safe
function verifyHMAC(data: string, expectedHmac: string): boolean {
  const actualHmac = createHMAC(data);
  // ✅ Comparaison en temps constant (résiste aux timing attacks)
  return crypto.timingSafeEqual(
    Buffer.from(actualHmac, 'hex'),
    Buffer.from(expectedHmac, 'hex')
  );
}

// Use case : vérifier un webhook (ex: Stripe, GitHub)
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  const signature = req.headers['stripe-signature'] as string;
  const payload = req.body.toString();

  const expectedSig = crypto
    .createHmac('sha256', process.env.STRIPE_WEBHOOK_SECRET!)
    .update(payload)
    .digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
    return res.status(403).json({ error: 'Signature invalide' });
  }

  // Traiter l'événement webhook...
  res.json({ received: true });
});
```

---

## 3. Chiffrement symétrique

### 3.1 AES-256-GCM — Authenticated Encryption

AES-GCM fournit à la fois **confidentialité** et **intégrité** (authenticated encryption). C'est le standard recommandé.

```typescript
import crypto from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;  // 256 bits
const IV_LENGTH = 12;   // 96 bits pour GCM (recommandé NIST)
const TAG_LENGTH = 16;  // 128 bits

// La clé doit venir d'un secret sécurisé
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');
// Générer une clé : crypto.randomBytes(32).toString('hex')

interface EncryptedData {
  iv: string;       // Initialization Vector (unique par chiffrement)
  encrypted: string; // Données chiffrées
  tag: string;       // Authentication tag (intégrité)
}

function encrypt(plaintext: string): EncryptedData {
  // ✅ IV unique pour CHAQUE opération de chiffrement
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv, {
    authTagLength: TAG_LENGTH,
  });

  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return {
    iv: iv.toString('hex'),
    encrypted,
    tag: cipher.getAuthTag().toString('hex'),
  };
}

function decrypt(data: EncryptedData): string {
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    ENCRYPTION_KEY,
    Buffer.from(data.iv, 'hex'),
    { authTagLength: TAG_LENGTH }
  );

  decipher.setAuthTag(Buffer.from(data.tag, 'hex'));

  let decrypted = decipher.update(data.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}
```

### 3.2 Gestion des IV/Nonces

```
╔══════════════════════════════════════════════════════════════╗
║  RÈGLE ABSOLUE : ne JAMAIS réutiliser un IV/nonce           ║
║  avec la même clé. Cela compromet la confidentialité.       ║
╚══════════════════════════════════════════════════════════════╝

Clé + IV → Keystream unique
Même Clé + Même IV → Même Keystream → XOR des plaintexts = catastrophe
```

```typescript
// ✅ Toujours générer un IV aléatoire
const iv = crypto.randomBytes(12); // 96 bits pour GCM

// ✅ Stocker l'IV avec le ciphertext (l'IV n'est pas secret)
const stored = `${iv.toString('hex')}:${encrypted}:${tag.toString('hex')}`;

// Format de stockage compact
function encryptCompact(plaintext: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  let enc = cipher.update(plaintext, 'utf8', 'hex');
  enc += cipher.final('hex');
  const tag = cipher.getAuthTag();
  // iv:ciphertext:tag — tout est nécessaire pour déchiffrer
  return `${iv.toString('hex')}:${enc}:${tag.toString('hex')}`;
}

function decryptCompact(data: string): string {
  const [ivHex, encHex, tagHex] = data.split(':');
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    ENCRYPTION_KEY,
    Buffer.from(ivHex, 'hex')
  );
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  let dec = decipher.update(encHex, 'hex', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}
```

---

## 4. Chiffrement asymétrique

### 4.1 RSA — Chiffrement et signatures

```typescript
import crypto from 'node:crypto';

// Générer une paire de clés RSA
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Chiffrer avec la clé publique
function rsaEncrypt(data: string, pubKey: string): string {
  const encrypted = crypto.publicEncrypt(
    {
      key: pubKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(data)
  );
  return encrypted.toString('base64');
}

// Déchiffrer avec la clé privée
function rsaDecrypt(encryptedData: string, privKey: string): string {
  const decrypted = crypto.privateDecrypt(
    {
      key: privKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(encryptedData, 'base64')
  );
  return decrypted.toString('utf8');
}
```

### 4.2 Signatures numériques

```typescript
// Signer un message (prouve l'origine et l'intégrité)
function sign(data: string, privKey: string): string {
  const signer = crypto.createSign('SHA256');
  signer.update(data);
  return signer.sign(privKey, 'base64');
}

// Vérifier une signature
function verifySignature(data: string, signature: string, pubKey: string): boolean {
  const verifier = crypto.createVerify('SHA256');
  verifier.update(data);
  return verifier.verify(pubKey, signature, 'base64');
}

// Use case : JWT avec RS256
// Le serveur d'authentification SIGNE avec la clé privée
// Les microservices VÉRIFIENT avec la clé publique
// → La clé publique peut être partagée librement
```

### 4.3 ECDSA — Alternative moderne à RSA

```typescript
// ECDSA : clés plus petites, même niveau de sécurité
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'P-256',  // secp256r1, 128 bits de sécurité
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Signer avec ECDSA
function ecdsaSign(data: string, privKey: string): string {
  return crypto.sign('sha256', Buffer.from(data), privKey).toString('base64');
}

// Vérifier
function ecdsaVerify(data: string, signature: string, pubKey: string): boolean {
  return crypto.verify(
    'sha256',
    Buffer.from(data),
    pubKey,
    Buffer.from(signature, 'base64')
  );
}
```

### Comparaison RSA vs ECDSA

| | RSA-4096 | ECDSA P-256 |
|---|---|---|
| Taille de clé | 4096 bits | 256 bits |
| Sécurité équivalente | ~128 bits | ~128 bits |
| Performance signature | Lente | Rapide |
| Performance vérification | Rapide | Moyenne |
| Taille signature | ~512 bytes | ~64 bytes |

---

## 5. TLS/SSL

### 5.1 Handshake TLS 1.3

```
Client                                    Serveur
  │                                          │
  ├── ClientHello ──────────────────────────►│
  │   (supported ciphers, key share)         │
  │                                          │
  │◄── ServerHello ──────────────────────────┤
  │   (chosen cipher, key share,             │
  │    certificate, verify)                  │
  │                                          │
  ├── Finished ────────────────────────────►│
  │                                          │
  │◄── Finished ─────────────────────────────┤
  │                                          │
  │←— Application Data (chiffré) ——→│
```

TLS 1.3 par rapport à 1.2 :
- **1-RTT** au lieu de 2-RTT (plus rapide)
- Algorithmes obsolètes supprimés (RC4, 3DES, SHA-1)
- **Forward secrecy** obligatoire (compromission d'une clé ne compromet pas les sessions passées)

### 5.2 Configuration HTTPS en Node.js

```typescript
import https from 'node:https';
import fs from 'node:fs';

const server = https.createServer({
  key: fs.readFileSync('./certs/private-key.pem'),
  cert: fs.readFileSync('./certs/certificate.pem'),
  ca: fs.readFileSync('./certs/ca-chain.pem'),

  // ✅ Configuration sécurisée
  minVersion: 'TLSv1.2',            // Minimum TLS 1.2
  ciphers: [
    'TLS_AES_256_GCM_SHA384',       // TLS 1.3
    'TLS_CHACHA20_POLY1305_SHA256', // TLS 1.3
    'TLS_AES_128_GCM_SHA256',       // TLS 1.3
  ].join(':'),
}, app);

// ✅ Rediriger HTTP vers HTTPS
import http from 'node:http';

http.createServer((req, res) => {
  res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
  res.end();
}).listen(80);
```

### 5.3 Let's Encrypt et ACME

```bash
# Installation de Certbot
sudo apt install certbot

# Obtenir un certificat automatiquement
sudo certbot certonly --standalone -d myapp.com

# Renouvellement automatique (cron)
0 0 1 * * certbot renew --quiet
```

### 5.4 HSTS — HTTP Strict Transport Security

```typescript
// Forcer HTTPS via le header HSTS
app.use(helmet.hsts({
  maxAge: 31536000,        // 1 an
  includeSubDomains: true,
  preload: true,           // Inclusion dans la preload list des navigateurs
}));
```

---

## 6. Gestion des secrets

### 6.1 Variables d'environnement

```bash
# .env (LOCAL UNIQUEMENT — jamais commité)
DATABASE_URL=postgres://user:pass@host/db
JWT_SECRET=un-secret-tres-long-et-aleatoire
ENCRYPTION_KEY=a1b2c3d4e5f6...
STRIPE_SECRET_KEY=sk_live_...
```

```gitignore
# .gitignore — OBLIGATOIRE
.env
.env.local
.env.production
*.pem
*.key
```

```typescript
// ✅ Validation des variables d'environnement au démarrage
import { z } from 'zod';

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']),
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  ENCRYPTION_KEY: z.string().length(64), // 32 bytes en hex
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
});

// Échoue au démarrage si une variable manque
const env = EnvSchema.parse(process.env);
export default env;
```

### 6.2 Vaults et gestionnaires de secrets

```typescript
// AWS Secrets Manager
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

const client = new SecretsManagerClient({ region: 'eu-west-1' });

async function getSecret(secretName: string): Promise<string> {
  const command = new GetSecretValueCommand({ SecretId: secretName });
  const response = await client.send(command);
  if (!response.SecretString) throw new Error('Secret non trouvé');
  return response.SecretString;
}

// Charger les secrets au démarrage
async function loadSecrets() {
  const dbSecret = JSON.parse(await getSecret('prod/database'));
  const jwtSecret = await getSecret('prod/jwt-key');

  return {
    databaseUrl: `postgres://${dbSecret.username}:${dbSecret.password}@${dbSecret.host}/${dbSecret.database}`,
    jwtSecret,
  };
}
```

### 6.3 Rotation de clés

```typescript
// Stratégie de rotation : supporter plusieurs versions de clés
interface KeyVersion {
  id: string;
  key: Buffer;
  createdAt: Date;
  active: boolean;  // Seule la clé active est utilisée pour chiffrer
}

const keys: KeyVersion[] = [
  { id: 'v2', key: Buffer.from(process.env.ENCRYPTION_KEY_V2!, 'hex'), createdAt: new Date('2025-01-01'), active: true },
  { id: 'v1', key: Buffer.from(process.env.ENCRYPTION_KEY_V1!, 'hex'), createdAt: new Date('2024-01-01'), active: false },
];

function encryptWithVersion(plaintext: string): string {
  const activeKey = keys.find(k => k.active)!;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', activeKey.key, iv);
  let enc = cipher.update(plaintext, 'utf8', 'hex');
  enc += cipher.final('hex');
  const tag = cipher.getAuthTag();
  // Préfixer avec la version de clé
  return `${activeKey.id}:${iv.toString('hex')}:${enc}:${tag.toString('hex')}`;
}

function decryptWithVersion(data: string): string {
  const [version, ivHex, encHex, tagHex] = data.split(':');
  const keyVersion = keys.find(k => k.id === version);
  if (!keyVersion) throw new Error(`Clé version ${version} non trouvée`);

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    keyVersion.key,
    Buffer.from(ivHex, 'hex')
  );
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  let dec = decipher.update(encHex, 'hex', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}

// Migration : re-chiffrer les données avec la nouvelle clé
async function rotateEncryptedData() {
  const rows = await db.query("SELECT id, encrypted_data FROM sensitive_data");
  for (const row of rows) {
    const decrypted = decryptWithVersion(row.encrypted_data);
    const reEncrypted = encryptWithVersion(decrypted); // Utilise la clé active (v2)
    await db.query(
      'UPDATE sensitive_data SET encrypted_data = $1 WHERE id = $2',
      [reEncrypted, row.id]
    );
  }
}
```

---

## 7. Exemples pratiques avec Node.js `crypto`

### 7.1 Générer des valeurs aléatoires sécurisées

```typescript
import crypto from 'node:crypto';

// Token aléatoire (pour reset password, invitations, etc.)
const token = crypto.randomBytes(32).toString('hex'); // 64 chars hex

// UUID v4 cryptographiquement sûr
const uuid = crypto.randomUUID();

// Nombre aléatoire sécurisé dans un intervalle
function secureRandomInt(min: number, max: number): number {
  const range = max - min;
  const bytesNeeded = Math.ceil(Math.log2(range) / 8);
  let randomValue: number;
  do {
    randomValue = parseInt(crypto.randomBytes(bytesNeeded).toString('hex'), 16);
  } while (randomValue >= range);
  return min + randomValue;
}
```

### 7.2 Dérivation de clé (KDF)

```typescript
// Dériver une clé de chiffrement à partir d'un mot de passe
function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 32, { N: 16384, r: 8, p: 1 }, (err, key) => {
      if (err) reject(err);
      resolve(key);
    });
  });
}

// HKDF (HMAC-based Key Derivation Function)
function hkdfDerive(
  inputKey: Buffer,
  salt: Buffer,
  info: string,
  length: number
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.hkdf('sha256', inputKey, salt, info, length, (err, key) => {
      if (err) reject(err);
      resolve(Buffer.from(key));
    });
  });
}
```

### 7.3 Résumé : quel outil pour quel besoin

| Besoin | Solution |
|---|---|
| Hasher un mot de passe | argon2id (ou bcrypt) |
| Vérifier l'intégrité d'un fichier | SHA-256 |
| Authentifier un message (webhook) | HMAC-SHA256 |
| Chiffrer des données au repos | AES-256-GCM |
| Signer un JWT | RS256 ou ES256 |
| Communiquer de manière sécurisée | TLS 1.3 |
| Générer un token aléatoire | `crypto.randomBytes()` |
| Stocker un secret | Vault / env vars (pas le code) |

---

## 8. Récapitulatif

### Règles fondamentales

1. **Ne pas inventer** — utiliser des algorithmes standards et des bibliothèques auditées
2. **Ne jamais réutiliser** un IV/nonce avec la même clé
3. **Comparer en temps constant** — `crypto.timingSafeEqual()` pour les secrets
4. **Stocker les secrets hors du code** — env vars, vaults, jamais dans Git
5. **Rotation des clés** — planifier et supporter plusieurs versions
6. **TLS partout** — pas d'exception, même en interne
7. **Authenticated encryption** — AES-GCM plutôt que AES-CBC seul

### Ressources

- [Node.js Crypto Documentation](https://nodejs.org/api/crypto.html)
- [OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [Latacora — Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html)

---

> Ce module conclut la série sur les fondamentaux de la sécurité applicative. Continuez à pratiquer avec les labs et exercices pour solidifier vos connaissances.
