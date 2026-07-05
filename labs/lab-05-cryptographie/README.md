<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Lab 05 — Cryptographie appliquée (défensif)

> **Outcome :** à la fin, tu sais chiffrer/déchiffrer une donnée sensible en **AES-256-GCM** avec un **IV unique par opération**, un **tag d'authentification**, une **clé hors du code**, et générer des tokens via un **CSPRNG** — en corrigeant un module de chiffrement fragile.
> **Vrai outil :** `node:crypto` (module natif Node ≥ 18) puis `crypto.subtle` (Web Crypto API). Exécution réelle via `tsx`. **Aucun harnais simulé** — pas de XOR maison, pas de faux HMAC.
> **Feedback :** le coach valide en session (relit le code + fait tourner un cas altéré). Pas de test-runner auto-correcteur.
>
> **Angle : DÉFENSIF.** Tu **durcis** un chiffrement pour protéger des données de mineurs. On ne casse aucun système tiers.

---

## Énoncé

Tu reprends `utils/crypto.ts` du back-office TribuZen. Il « protège » les fiches médicales des enfants. Il **tourne** en démo (chiffre puis déchiffre, le texte revient) — mais il est **dangereux**. Ta mission : le corriger sans changer sa signature publique (`encrypt`, `decrypt`, `newShareToken`).

**Code fragile de départ (à copier dans `crypto-fragile.ts`) :**

```typescript
// crypto-fragile.ts — NE PAS livrer. À corriger.
import crypto from 'node:crypto'

const KEY = 'tribuzen-secret-key-2026' // clé en dur

export function encrypt(plaintext: string): string {
  const cipher = crypto.createCipheriv('aes-256-ecb', Buffer.from(KEY.padEnd(32)), null)
  let enc = cipher.update(plaintext, 'utf8', 'base64')
  enc += cipher.final('base64')
  return enc
}

export function decrypt(payload: string): string {
  const decipher = crypto.createDecipheriv('aes-256-ecb', Buffer.from(KEY.padEnd(32)), null)
  let dec = decipher.update(payload, 'base64', 'utf8')
  dec += decipher.final('utf8')
  return dec
}

export function newShareToken(): string {
  return Math.random().toString(36).slice(2)
}
```

**Le cahier des charges de la version corrigée :**

1. **Clé hors du code** — lue depuis `process.env.ENCRYPTION_KEY` (32 octets en hex = 64 caractères). Le module **jette au démarrage** si la clé est absente ou de mauvaise taille.
2. **AES-256-GCM** — plus jamais ECB. IV **unique** (12 octets, CSPRNG) à chaque `encrypt`, **tag d'authentification** stocké avec le chiffré.
3. **Format de stockage** : `version:iv:ciphertext:tag` (hex), pour préparer la rotation de clé.
4. **Déchiffrement authentifié** — une altération du chiffré ou du tag **fait échouer** `decrypt` (throw), au lieu de rendre un clair corrompu.
5. **`newShareToken`** — 32 octets via `crypto.randomBytes`, encodés en `base64url`. Plus de `Math.random`.

**Pas de gap-fill** — tu écris le module corrigé complet à partir du starter ci-dessous.

### Starter minimal

Crée `crypto-secure.ts` :

```typescript
// crypto-secure.ts — starter
import crypto from 'node:crypto'

const ALGO = 'aes-256-gcm'
const KEY_VERSION = 'v1'

// TODO 1 : charger KEY depuis process.env.ENCRYPTION_KEY (Buffer hex, 32 octets), jeter si invalide

export function encrypt(plaintext: string): string {
  // TODO 2 : IV aléatoire 12 octets, cipher GCM, récupérer le tag, renvoyer version:iv:ct:tag
  throw new Error('à implémenter')
}

export function decrypt(payload: string): string {
  // TODO 3 : parser le format, vérifier la version, setAuthTag, déchiffrer (throw si altéré)
  throw new Error('à implémenter')
}

export function newShareToken(): string {
  // TODO 4 : 32 octets CSPRNG en base64url
  throw new Error('à implémenter')
}
```

Génère une clé de test et lance :

```bash
# génère une clé 32 octets et exécute un smoke test
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# copie la valeur dans ENCRYPTION_KEY puis :
ENCRYPTION_KEY=<clé_hex> npx tsx crypto-secure.ts
```

(Sous PowerShell : `$env:ENCRYPTION_KEY="<clé_hex>"; npx tsx crypto-secure.ts`.)

Ajoute en bas de fichier un petit `main` manuel (pas un framework de test) pour **voir** le comportement :

```typescript
if (require.main === module) {
  const secret = 'Allergie : arachide. EpiPen dans le sac.'
  const blob = encrypt(secret)
  console.log('chiffré :', blob)
  console.log('déchiffré :', decrypt(blob))

  // Preuve d'intégrité : on altère 1 caractère du ciphertext → decrypt DOIT jeter
  const parts = blob.split(':')
  parts[2] = parts[2].replace(/.$/, (c) => (c === 'a' ? 'b' : 'a'))
  try {
    decrypt(parts.join(':'))
    console.error('ÉCHEC : le déchiffrement altéré aurait dû jeter')
  } catch {
    console.log('OK : altération détectée (tag GCM)')
  }

  // Preuve d'IV unique : deux chiffrés du même clair doivent DIFFÉRER
  console.log('IV unique ?', encrypt(secret) !== encrypt(secret))
}
```

---

## Étapes (en friction)

1. **Charge la clé** — `Buffer.from(process.env.ENCRYPTION_KEY!, 'hex')` ; `throw` si `length !== 32`. Comprends pourquoi une clé en dur est indéfendable (Git, rotation impossible).
2. **Écris `encrypt`** — `crypto.randomBytes(12)` pour l'IV, `createCipheriv('aes-256-gcm', KEY, iv)`, concatène `update`+`final`, récupère `getAuthTag()`, renvoie `version:iv:ct:tag` en hex.
3. **Écris `decrypt`** — split, vérifie la version, `createDecipheriv`, `setAuthTag`, déchiffre. Ne rattrape **pas** l'erreur d'altération : laisse-la remonter.
4. **Écris `newShareToken`** — `crypto.randomBytes(32).toString('base64url')`.
5. **Fais tourner le `main`** — vérifie les 3 preuves : round-trip OK, altération détectée, IV unique (deux chiffrés diffèrent).
6. **Cas limites** — que se passe-t-il si `ENCRYPTION_KEY` est absent ? Si on déchiffre un blob d'une autre version de clé ? Le module doit **jeter clairement**, pas rendre n'importe quoi.
7. **Bonus Web Crypto** — réécris `encrypt`/`decrypt` avec `crypto.subtle` (`generateKey`/`importKey`, `AES-GCM`, `getRandomValues` pour l'IV). Constate que l'API est isomorphe navigateur/Node.

---

## Corrigé complet commenté

```typescript
// crypto-secure.ts — corrigé (node:crypto)
import crypto from 'node:crypto'

const ALGO = 'aes-256-gcm'
const KEY_VERSION = 'v1' // préfixe → permet la rotation (déchiffrer l'ancien, chiffrer avec le neuf)

// (1) Clé HORS du code, lue à l'import. 32 octets = 64 hex.
//     En prod : DEK wrappée par une KEK au KMS (cf. module 05 §2.6). Ici : env pour le lab.
const KEY = Buffer.from(process.env.ENCRYPTION_KEY ?? '', 'hex')
if (KEY.length !== 32) {
  // Échoue AU DÉMARRAGE, pas au premier chiffrement en prod.
  throw new Error('ENCRYPTION_KEY manquante ou invalide : attendu 32 octets (64 hex)')
}

export function encrypt(plaintext: string): string {
  // (2) IV UNIQUE par opération : 12 octets (96 bits, recommandé GCM), via CSPRNG.
  //     Réutiliser un IV avec la même clé casserait GCM → randomBytes à CHAQUE appel.
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv(ALGO, KEY, iv)
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  // (2) tag d'authentification (16 octets) : c'est lui qui garantit l'intégrité.
  const tag = cipher.getAuthTag()
  // (3) format version:iv:ct:tag — l'IV et le tag ne sont PAS secrets, on les stocke à côté.
  return [KEY_VERSION, iv.toString('hex'), enc.toString('hex'), tag.toString('hex')].join(':')
}

export function decrypt(payload: string): string {
  const [version, ivHex, encHex, tagHex] = payload.split(':')
  // (3) rotation : on refuse ce qu'on ne sait pas déchiffrer, au lieu de deviner.
  if (version !== KEY_VERSION) throw new Error(`version de clé inconnue : ${version}`)

  const decipher = crypto.createDecipheriv(ALGO, KEY, Buffer.from(ivHex, 'hex'))
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'))
  // (4) si le ciphertext OU le tag ont été altérés, final() JETTE.
  //     On ne rattrape pas ici : un clair corrompu ne doit jamais sortir de decrypt().
  return Buffer.concat([
    decipher.update(Buffer.from(encHex, 'hex')),
    decipher.final(),
  ]).toString('utf8')
}

export function newShareToken(): string {
  // (5) CSPRNG, jamais Math.random. base64url = sûr en URL (lien de partage de fiche).
  return crypto.randomBytes(32).toString('base64url')
}
```

**Pourquoi ce corrigé est correct :**
- **Clé hors du code**, validée à l'import → pas de secret dans Git, échec immédiat si mal configurée.
- **AES-256-GCM** (chiffrement authentifié) remplace ECB : plus de motifs visibles, et l'intégrité est intégrée.
- **IV neuf à chaque `encrypt`** (`randomBytes(12)`) → deux chiffrés du même clair diffèrent ; aucun IV rejoué.
- **Tag d'authentification** stocké et vérifié → toute altération fait **échouer** `decrypt` (on ne rattrape pas l'erreur).
- **Version de clé** dans le format → la rotation est possible sans casser l'existant.
- **`newShareToken`** utilise un CSPRNG → tokens imprévisibles.

**Bonus — variante Web Crypto (isomorphe navigateur/Node) :**

```typescript
// crypto-webcrypto.ts — même contrat, API standard crypto.subtle
const subtle = globalThis.crypto.subtle

// La clé arrive en 32 octets (importée depuis un KMS/env, jamais en dur)
async function importKey(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

async function encrypt(key: CryptoKey, plaintext: string): Promise<string> {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12)) // IV unique, CSPRNG
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext))
  // GCM concatène ciphertext‖tag ; on stocke iv:blob en hex
  const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
  return `v1:${hex(iv)}:${hex(new Uint8Array(ct))}`
}

async function decrypt(key: CryptoKey, payload: string): Promise<string> {
  const [version, ivHex, blobHex] = payload.split(':')
  if (version !== 'v1') throw new Error(`version inconnue : ${version}`)
  const iv = Uint8Array.from(Buffer.from(ivHex, 'hex'))
  const blob = Uint8Array.from(Buffer.from(blobHex, 'hex'))
  // decrypt() REJETTE si le tag ne colle pas (intégrité)
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv }, key, blob)
  return new TextDecoder().decode(plain)
}
```

---

## Grille d'auto-évaluation

| Critère | Acquis si… |
|---|---|
| Clé hors du code | la clé vient de `process.env`, le module **jette au démarrage** si absente ou ≠ 32 octets, et tu expliques pourquoi une clé en dur est indéfendable (Git, rotation impossible) |
| ECB → GCM | tu as banni `aes-256-ecb` pour `aes-256-gcm` et sais dire ce que GCM apporte qu'ECB n'a pas (authentification + non-déterminisme) |
| IV unique | un IV **12 octets CSPRNG** est généré à **chaque** `encrypt`, et deux chiffrés du même clair **diffèrent** (preuve exécutée) |
| Tag d'authentification | le tag GCM est stocké puis re-vérifié ; une altération d'1 caractère du chiffré **fait jeter** `decrypt` (preuve exécutée) |
| Format versionné | le blob suit `version:iv:ct:tag` et `decrypt` **rejette** une version inconnue au lieu de rendre du clair corrompu |
| CSPRNG pour tokens | `newShareToken` utilise `crypto.randomBytes` (base64url), plus jamais `Math.random` — et tu sais pourquoi `Math.random` n'est pas cryptographique |
| Web Crypto (bonus) | tu retrouves le même comportement avec `crypto.subtle` et constates l'API isomorphe Node/navigateur |

**Seuil :** « Acquis » sur clé hors du code, IV unique et tag d'authentification — les trois gardes sans lesquelles le chiffrement est décoratif.

---

## Coach — conduite de session

- **Fais tourner le code fragile d'abord.** Il chiffre/déchiffre « correctement » en démo : Sylvain doit **voir** que « ça marche » ne veut rien dire. Relance : « pourquoi ce module qui tourne est-il quand même dangereux ? ».
- **Piège à débusquer #1 — ECB déterministe :** demande-lui de chiffrer **deux fois le même clair** avec la version fragile. Les chiffrés sont identiques → fuite de structure (le fameux « pingouin ECB »). Tant qu'il ne l'a pas vu, GCM reste abstrait.
- **Piège à débusquer #2 — « je rattrape l'erreur d'altération » :** s'il entoure `decrypt` d'un `try/catch` qui renvoie une valeur, arrête-le : l'échec du tag **doit** remonter. Un clair silencieusement corrompu est pire qu'une exception.
- **Piège à débusquer #3 — IV réutilisé :** s'il fixe l'IV « pour simplifier », rappelle que la réutilisation d'IV en GCM est catastrophique (perte de confidentialité + forge). L'IV se génère à chaque appel.
- **Ancrage TribuZen :** ce sont les **fiches médicales des enfants** (allergies, traitements). Une fuite = donnée de santé de mineur exposée. Le durcissement n'est pas cosmétique.
- **Si silence / blocage :** propose de partir de la preuve « deux chiffrés doivent différer » et de remonter à ce qu'il faut pour l'obtenir (IV unique). La preuve exécutée débloque la théorie.

---

## Variante J+30 (fading)

**Même objectif, contraintes ajoutées.** Reproduis le module `node:crypto` **de mémoire, en 30 minutes**, sans rouvrir ce corrigé ni le module 05, avec ces ajouts :

1. **Rotation réelle** — supporte **deux** clés (`ENCRYPTION_KEY_V1`, `ENCRYPTION_KEY_V2`). `encrypt` chiffre toujours avec la version **active** (`v2`) ; `decrypt` sait déchiffrer `v1` **et** `v2` selon le préfixe. Écris une fonction `rotate(payload)` qui redéchiffre un blob `v1` et le rechiffre en `v2`.
2. **Vérif d'un webhook** — ajoute `verifyWebhook(rawBody, signatureHex, secret)` qui recalcule un HMAC-SHA256 et compare via `crypto.timingSafeEqual` (attention aux longueurs).
3. **Critère de réussite :** le `main` prouve que (a) un blob `v1` se déchiffre et se `rotate` en `v2`, (b) une signature webhook falsifiée est rejetée, (c) l'altération d'un chiffré `v2` fait toujours jeter `decrypt`.

---

## Application TribuZen

Dans le repo `smaurier/tribuzen` (back-office NestJS), ce code vit ici :

```
tribuzen-api/
  src/
    crypto/
      field-crypto.service.ts   ← encrypt/decrypt AES-256-GCM (version:iv:ct:tag)
      key-provider.ts           ← DEK wrappée par KEK au KMS, versions de clé
    common/
      random.ts                 ← newShareToken (crypto.randomBytes)
```

**Différences par rapport au lab :**

- La clé ne vient **pas** de `process.env` en clair mais d'une **DEK wrappée par une KEK** au KMS (cf. module 05 §2.6) ; `key-provider.ts` la déchiffre au démarrage.
- Le chiffrement de champ est branché comme **transformer** d'entité (NestJS/Prisma) : les champs santé de `child-medical.entity.ts` sont chiffrés/déchiffrés de façon transparente à l'écriture/lecture.
- La rotation de clé tourne en tâche planifiée (re-chiffrement progressif des lignes `v1` → `v2`).

**Commit cible :**
```
feat(crypto): chiffrement de champ AES-256-GCM (IV unique, tag, version de clé) pour données santé
```
