---
titre: Cryptographie appliquée — hachage vs chiffrement vs encodage, symétrique/asymétrique, TLS, clés
cours: 14-securite-applicative
notions: ["hachage vs chiffrement vs encodage", "chiffrement symétrique AES-256-GCM", "IV/nonce unique par opération", "jamais ECB", "chiffrement asymétrique RSA-OAEP / ECC (Curve25519)", "signatures numériques", "HMAC + timingSafeEqual", "TLS 1.3 & forward secrecy", "gestion de clés (KEK/DEK, rotation)", "aléa cryptographique (CSPRNG)", "ne pas rouler sa propre crypto"]
outcomes:
  - "sait distinguer hachage, chiffrement et encodage et choisir le bon outil pour un besoin donné"
  - "sait chiffrer/déchiffrer une donnée sensible en AES-256-GCM avec un IV unique par opération (Web Crypto et node:crypto)"
  - "sait quand utiliser du symétrique (AES) vs de l'asymétrique (RSA-OAEP, ECC) et pourquoi ECC est préféré à RSA aujourd'hui"
  - "sait vérifier un webhook via HMAC en comparaison temps constant (timingSafeEqual)"
  - "sait organiser des clés (KEK/DEK), générer de l'aléa cryptographique et éviter les pièges (ECB, IV réutilisé, Math.random, crypto maison)"
prerequis:
  - "Introduction sécurité — CIA (confidentialité/intégrité/disponibilité), defense in depth (module 00)"
  - "Authentification — hachage de MOT DE PASSE argon2id/bcrypt, sel/poivre (module 03)"
  - "Autorisation — moindre privilège, protection des données par accès (module 04)"
next: 06-headers-securite
libs: []
tribuzen: back-office TribuZen — chiffrement au repos des données sensibles de mineurs (santé, allergies, notes)
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Cryptographie appliquée — hachage vs chiffrement vs encodage, symétrique/asymétrique, TLS, clés

> **Outcomes — tu sauras FAIRE :** distinguer hachage / chiffrement / encodage, chiffrer une donnée sensible en AES-256-GCM avec un IV unique (Web Crypto et `node:crypto`), choisir entre symétrique et asymétrique, vérifier un webhook en HMAC temps constant, et organiser des clés (KEK/DEK) sans jamais rouler ta propre crypto.
> **Difficulté :** :star::star::star::star:
>
> **Angle : DÉFENSIF.** On assemble des primitives éprouvées pour **protéger** des données ; on montre les pièges (ECB, IV rejoué, `Math.random`) pour les **reconnaître et les corriger** dans TON code, jamais pour casser un système tiers.
>
> **Portée :** ce module couvre la **crypto appliquée aux données** (chiffrer au repos, signer, vérifier). Le **hachage de MOT DE PASSE** (argon2id, sel, poivre) a été traité au **module 03** — on n'y revient que pour rappeler qu'un mot de passe se **hache**, ne se **chiffre jamais**. Les **headers TLS/HSTS** côté HTTP sont détaillés au **module 06**. La **gestion des secrets d'infra** (vaults, KMS cloud) est survolée ici et approfondie au **module 10**.

## 1. Cas concret d'abord

Tu reprends le back-office TribuZen. Une nouvelle fonctionnalité stocke des **informations médicales d'enfants** (allergies, traitements) pour que les animateurs d'activité les voient. Un collègue a livré ce « chiffrement » pour les protéger en base. Ça « marche » en démo : on rechiffre, on redéchiffre, le texte revient.

```typescript
// utils/crypto.ts — AVANT. NE PAS copier en prod.
import crypto from 'node:crypto'

const KEY = 'tribuzen-secret-key-2026' // (1) clé en dur dans le code

export function encrypt(plaintext: string): string {
  // (2) AES en mode ECB — pas d'IV du tout
  const cipher = crypto.createCipheriv('aes-256-ecb', Buffer.from(KEY.padEnd(32)), null)
  let enc = cipher.update(plaintext, 'utf8', 'base64')
  enc += cipher.final('base64')
  return enc // (3) aucun tag d'authentification : rien ne détecte une altération
}

export function newShareToken(): string {
  // (4) "aléatoire" pour un lien de partage de fiche médicale
  return Math.random().toString(36).slice(2)
}
```

**Quatre trous que ce module va boucher :**

1. **Clé en dur dans le code** — versionnée dans Git, identique sur tous les environnements, impossible à faire tourner. Une clé vit **hors du code** (variable d'env, KMS) et se **fait tourner**.
2. **Mode ECB** — chaque bloc de 16 octets est chiffré indépendamment : deux blocs de clair identiques donnent deux blocs de chiffré **identiques**. Les motifs du clair transparaissent (l'image du « pingouin ECB » est le mème classique). ECB est **proscrit**.
3. **Pas d'authentification** — sans tag GCM, un attaquant peut modifier le chiffré ; au déchiffrement, on obtient un clair corrompu **sans erreur**. On veut du chiffrement **authentifié** (AES-GCM).
4. **`Math.random()`** — ce n'est **pas** un générateur cryptographique : ses sorties sont prédictibles. Un token de partage de fiche médicale doit venir d'un **CSPRNG** (`crypto.randomBytes` / `crypto.getRandomValues`).

À la fin du module, ce fichier chiffre en **AES-256-GCM** avec un **IV unique par opération**, un **tag d'authentification**, une **clé hors du code**, et génère ses tokens via un **CSPRNG**. C'est le fil rouge du lab.

---

## 2. Théorie complète, concise

### 2.1 Hachage vs chiffrement vs encodage (le tri fondamental)

Trois transformations qu'on confond sans cesse — elles ne servent **pas** au même but.

| | **Encodage** | **Hachage** | **Chiffrement** |
|---|---|---|---|
| Réversible | Oui, **sans** clé | **Non** (sens unique) | Oui, **avec** la clé |
| But | représenter/transporter | empreinte, intégrité | confidentialité |
| Clé | aucune | aucune (ou clé → HMAC) | oui |
| Exemples | Base64, hex, URL-encoding | SHA-256, SHA-3 | AES, RSA, ECC |

- **Encodage** (Base64…) = **zéro sécurité**. `Buffer.from('secret').toString('base64')` est lisible par quiconque le décode. Un JWT est *encodé*, pas *chiffré* : son contenu est en clair.
- **Hachage** = sens unique, pour vérifier l'**intégrité** (checksum d'un fichier) ou stocker un mot de passe (mais alors hash *lent* : argon2id — **module 03**). SHA-256 est parfait pour l'intégrité, **disqualifié** pour un mot de passe.
- **Chiffrement** = confidentialité **réversible avec la clé**. C'est le cœur de ce module.

> Un **mot de passe se hache** (irréversible), une **donnée métier se chiffre** (on doit la relire). Chiffrer un mot de passe est une faute : si la clé fuit, tous les mots de passe sont en clair.

### 2.2 Symétrique : AES-256-GCM

**Symétrique** = **une seule clé** chiffre et déchiffre. Rapide, pour les **volumes de données** (chiffrer une colonne en base, un fichier).

Le standard est **AES**. Ce qui compte autant que l'algo, c'est le **mode opératoire** :

- **AES-GCM** (ou CCM) — **chiffrement authentifié** (AEAD) : confidentialité **+** intégrité en une passe. Produit un **tag** qui détecte toute altération. **C'est le défaut à choisir.**
- **AES-CBC / CTR** — chiffrement seul, **sans** authentification intégrée : il faut ajouter un HMAC (Encrypt-then-MAC). Plus de pièces = plus d'erreurs. À éviter si GCM est dispo.
- **AES-ECB** — **proscrit** : pas d'IV, blocs indépendants, motifs du clair visibles.

**Taille de clé** : AES **128 bits minimum, 256 bits idéalement** (OWASP, vérifié 2026-07). On vise **AES-256-GCM**.

**IV / nonce** — vecteur d'initialisation :
- **12 octets (96 bits)** pour GCM (recommandation NIST / Web Crypto).
- **Unique pour CHAQUE opération** avec une clé donnée. **Réutiliser un IV avec la même clé casse GCM** (fuite du keystream, et pire, compromission de la clé d'authentification).
- L'IV **n'est pas secret** : on le stocke **à côté** du chiffré. On le **génère au hasard** (CSPRNG) à chaque `encrypt`.

```typescript
// node:crypto — AES-256-GCM, format compact iv:ciphertext:tag
import crypto from 'node:crypto'

const ALGO = 'aes-256-gcm'
const KEY = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex') // 32 octets = 64 hex, HORS du code

export function encrypt(plaintext: string): string {
  const iv = crypto.randomBytes(12)                    // IV UNIQUE, 96 bits, CSPRNG
  const cipher = crypto.createCipheriv(ALGO, KEY, iv)
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()                      // tag d'intégrité (16 octets)
  return [iv.toString('hex'), enc.toString('hex'), tag.toString('hex')].join(':')
}

export function decrypt(payload: string): string {
  const [ivHex, encHex, tagHex] = payload.split(':')
  const decipher = crypto.createDecipheriv(ALGO, KEY, Buffer.from(ivHex, 'hex'))
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'))      // sans le tag, final() jette si altéré
  return Buffer.concat([decipher.update(Buffer.from(encHex, 'hex')), decipher.final()]).toString('utf8')
}
```

### 2.3 Asymétrique : RSA et ECC

**Asymétrique** = **paire de clés** : une **publique** (partageable) et une **privée** (secrète). Ce qui est chiffré avec l'une se déchiffre avec l'autre. Lent → on ne chiffre **pas** de gros volumes avec, mais :

- **Chiffrement** : le monde chiffre avec ta clé publique, toi seul déchiffres (clé privée).
- **Signature** : tu signes avec ta clé **privée**, tout le monde vérifie avec ta clé **publique** (origine + intégrité). C'est le principe de RS256/ES256 pour les JWT (**module 08**).

**Algorithmes (OWASP, vérifié 2026-07) :**

| | **RSA** | **ECC (courbes elliptiques)** |
|---|---|---|
| Clé minimale | **2048 bits** (3072+ recommandé) | courbe sûre : **Curve25519 / P-256** |
| Sécurité ~128 bits | RSA-3072 | P-256 (256 bits de clé) |
| Vitesse / taille | lent, grosses clés/signatures | rapide, petites clés/signatures |
| Padding chiffrement | **OAEP** (jamais PKCS#1 v1.5 pour du neuf) | — |
| Préférence 2026 | legacy / interop | **préféré** (Curve25519 : X25519 chiffrement, Ed25519 signature) |

> **ECC est préféré à RSA aujourd'hui** : même sécurité pour des clés bien plus petites et des opérations plus rapides. On garde RSA surtout pour l'interopérabilité avec l'existant.

```typescript
// node:crypto — signature Ed25519 (courbe moderne, rapide)
import crypto from 'node:crypto'

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')

const message = Buffer.from('fiche #4217 validée')
const signature = crypto.sign(null, message, privateKey)          // signe avec la privée
const ok = crypto.verify(null, message, publicKey, signature)     // vérifie avec la publique
```

### 2.4 HMAC et comparaison en temps constant

**HMAC** = hachage **+ clé secrète** : prouve qu'un message vient de quelqu'un qui connaît la clé (intégrité **+** authenticité), sans chiffrer. Usage type : **vérifier un webhook** (Stripe, GitHub signent le payload).

Deux règles :
1. La clé du webhook est un **secret** (hors du code).
2. On compare les signatures en **temps constant** — `crypto.timingSafeEqual`. Une comparaison naïve (`===`) s'arrête au premier octet différent : le **temps** de réponse fuit combien d'octets étaient corrects, ce qui permet de reconstituer la signature octet par octet.

```typescript
import crypto from 'node:crypto'

function verifyWebhook(rawBody: Buffer, signatureHeader: string, secret: string): boolean {
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex')
  const a = Buffer.from(signatureHeader, 'hex')
  const b = Buffer.from(expected, 'hex')
  // timingSafeEqual exige des longueurs égales → on vérifie d'abord, sinon il jette
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}
```

### 2.5 TLS 1.3 : la crypto « en transit »

Tout ce qui précède protège la donnée **au repos**. **TLS** la protège **en transit** (chiffrement + intégrité + authentification du serveur via son certificat). Points à retenir :

- **TLS 1.3** : handshake **1-RTT** (plus rapide), algorithmes obsolètes supprimés (RC4, 3DES, SHA-1), **forward secrecy obligatoire** — la compromission de la clé privée du serveur ne déchiffre **pas** les sessions passées (chaque session dérive une clé éphémère).
- **Minimum TLS 1.2** en prod, TLS 1.3 préféré. Pas de TLS 1.0/1.1.
- Certificats gratuits via **Let's Encrypt / ACME**, renouvelés automatiquement.
- Forcer HTTPS côté application via **HSTS** → détaillé au **module 06 (headers)**.

En pratique, on ne code pas TLS : on le **configure** (reverse proxy, plateforme). Le rôle du dev est de ne **jamais** désactiver la vérification de certificat (`rejectUnauthorized: false` = trou béant).

### 2.6 Gestion de clés : KEK/DEK, stockage, rotation

Une clé de chiffrement est le point unique de défaillance. OWASP (vérifié 2026-07) recommande une hiérarchie à **deux niveaux** :

- **DEK** (Data Encryption Key) — chiffre réellement les données.
- **KEK** (Key Encryption Key) — chiffre la DEK. La KEK vit dans un **KMS/vault** ; on ne manipule que des DEK **chiffrées** (« wrapped »).

Règles :
- **Clés hors du code et hors de la base des données** qu'elles protègent (sinon une seule fuite donne tout).
- **Rotation** : périodique, après compromission suspectée, ou après un très gros volume chiffré. Prévoir dès le départ un **identifiant de version** dans le format stocké (`v2:iv:ct:tag`) pour déchiffrer l'ancien pendant qu'on chiffre avec le nouveau.
- **Générer de l'aléa** de clé et d'IV avec un **CSPRNG** (voir 2.7), jamais un mot de passe humain directement (passer par un KDF : scrypt/PBKDF2/HKDF).

### 2.7 Aléa cryptographique (CSPRNG) et la règle d'or

- **CSPRNG** = générateur pseudo-aléatoire **cryptographiquement sûr**, imprévisible même en connaissant les sorties passées.
  - Node : `crypto.randomBytes(n)`, `crypto.randomUUID()`, `crypto.randomInt()`.
  - Navigateur : `crypto.getRandomValues(new Uint8Array(n))`.
- **`Math.random()` n'est PAS cryptographique** — prévisible. Jamais pour un token, un IV, un sel, une clé.

> **La règle d'or : ne roule jamais ta propre crypto.** N'invente pas d'algorithme, n'assemble pas de primitives à la main si une brique éprouvée existe. Web Crypto et `node:crypto` (OpenSSL) sont audités ; ton XOR maison ne l'est pas. « Ça a l'air aléatoire » n'est pas une preuve de sécurité. Utilise une lib de haut niveau (`libsodium`, `jose` pour JWT/JWE) dès que possible.

---

## 3. Worked examples

### Exemple 1 — Chiffrer une fiche médicale au repos (Web Crypto, isomorphe)

`crypto.subtle` (Web Crypto API) marche dans le navigateur **et** dans Node moderne — c'est l'API standard et portable. On chiffre une note médicale en AES-256-GCM.

```typescript
// Web Crypto — AES-256-GCM. subtle est en secure context (HTTPS) ou dans Node.
const subtle = globalThis.crypto.subtle

// Génère une clé AES-256 (à stocker/wrapper via KMS ; ici en mémoire pour l'exemple)
async function newKey(): Promise<CryptoKey> {
  return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
}

async function encrypt(key: CryptoKey, plaintext: string) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12)) // IV UNIQUE, CSPRNG, 96 bits
  const data = new TextEncoder().encode(plaintext)
  // GCM produit ciphertext ‖ tag concaténés ; l'IV se stocke à côté (non secret)
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, data)
  return { iv, ciphertext: new Uint8Array(ct) }
}

async function decrypt(key: CryptoKey, iv: Uint8Array, ciphertext: Uint8Array) {
  // Si le ciphertext ou le tag ont été altérés, decrypt() REJETTE (intégrité garantie).
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext)
  return new TextDecoder().decode(plain)
}

// Usage
const key = await newKey()
const { iv, ciphertext } = await encrypt(key, 'Allergie : arachide. EpiPen dans le sac.')
const clair = await decrypt(key, iv, ciphertext) // → texte d'origine, ou throw si altéré
```

Points clés : **IV neuf à chaque `encrypt`** via `getRandomValues`, IV stocké **à côté** du chiffré, et l'intégrité est **gratuite** avec GCM — un chiffré modifié fait **échouer** le `decrypt` au lieu de rendre un clair pourri.

### Exemple 2 — Corriger le fichier fragile du §1

On reprend `utils/crypto.ts` du §1 et on bouche les quatre trous, version `node:crypto`.

```typescript
// utils/crypto.ts — APRÈS
import crypto from 'node:crypto'

// (1) clé HORS du code : 32 octets en hex dans l'env (généré une fois via
//     crypto.randomBytes(32).toString('hex')). En prod : wrapper via KMS (KEK/DEK).
const KEY = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex')
if (KEY.length !== 32) throw new Error('ENCRYPTION_KEY doit faire 32 octets (64 hex)')

const KEY_VERSION = 'v1' // (rotation) préfixe pour déchiffrer l'ancien après changement de clé

export function encrypt(plaintext: string): string {
  const iv = crypto.randomBytes(12)                     // (2)+(4) IV UNIQUE via CSPRNG
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv) // (2) GCM, plus jamais ECB
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()                       // (3) tag d'authentification
  return [KEY_VERSION, iv.toString('hex'), enc.toString('hex'), tag.toString('hex')].join(':')
}

export function decrypt(payload: string): string {
  const [version, ivHex, encHex, tagHex] = payload.split(':')
  if (version !== KEY_VERSION) throw new Error(`version de clé inconnue: ${version}`)
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(ivHex, 'hex'))
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'))       // (3) altération → final() jette
  return Buffer.concat([decipher.update(Buffer.from(encHex, 'hex')), decipher.final()]).toString('utf8')
}

export function newShareToken(): string {
  return crypto.randomBytes(32).toString('base64url')   // (4) CSPRNG, pas Math.random
}
```

Ce qui a changé : clé hors du code + versionnée pour la rotation, **AES-256-GCM** au lieu d'ECB, **IV unique** par opération, **tag d'authentification** qui fait échouer tout déchiffrement altéré, et tokens via **CSPRNG**.

---

## 4. Pièges & misconceptions

### PIÈGE #1 — « Base64, c'est du chiffrement »
Non. Base64 est un **encodage** réversible **sans clé** : quiconque le décode lit le contenu. Un JWT est encodé (lisible), pas chiffré. Pour cacher une donnée → **chiffrement** (AES). Pour la transporter → encodage. Ne jamais « sécuriser » en Base64.

### PIÈGE #2 — Chiffrer un mot de passe au lieu de le hacher
Un mot de passe se **hache** (argon2id, irréversible — **module 03**), il ne se **chiffre jamais** : si la clé fuit, tous les mots de passe redeviennent lisibles. Le chiffrement est pour les données qu'on doit **relire** (fiche médicale), pas pour un secret d'authentification.

### PIÈGE #3 — Mode ECB (ou AES « sans mode »)
ECB chiffre chaque bloc indépendamment → deux blocs de clair identiques donnent le même chiffré, les motifs transparaissent. **Toujours un mode authentifié : AES-GCM.** Si tu vois `aes-256-ecb` ou un `createCipheriv` sans IV, c'est un bug.

### PIÈGE #4 — Réutiliser un IV/nonce avec la même clé
En GCM, **rejouer un IV avec la même clé est catastrophique** : le keystream se répète et la clé d'authentification peut être récupérée. L'IV doit être **neuf et aléatoire (CSPRNG) à chaque chiffrement**. Il n'est pas secret → on le stocke à côté du chiffré.

### PIÈGE #5 — `Math.random()` pour du sécuritaire
`Math.random()` est prévisible : un token de reset, un IV, un sel, une clé générés ainsi sont devinables. Toujours un **CSPRNG** : `crypto.randomBytes` (Node) ou `crypto.getRandomValues` (navigateur).

### PIÈGE #6 — Comparer des secrets avec `===`
`===` s'arrête au premier octet différent → le timing révèle combien d'octets étaient corrects (timing attack). Pour comparer une signature/HMAC/token, utiliser **`crypto.timingSafeEqual`** (longueurs égales requises).

### PIÈGE #7 — Rouler sa propre crypto
XOR maison, « chiffrement » par substitution, algo inventé « parce qu'il a l'air aléatoire » : tous cassables. **N'invente rien.** Utilise `node:crypto` / Web Crypto (OpenSSL, audités), ou une lib de haut niveau (`libsodium`, `jose`). La crypto se réutilise, elle ne se réécrit pas.

### PIÈGE #8 — Chiffrement seul ≠ intégrité
AES-CBC/CTR **sans** MAC chiffre mais ne détecte **pas** l'altération : un attaquant peut modifier le chiffré, tu déchiffres un clair corrompu sans alerte. Utiliser un mode **authentifié (GCM)** ou ajouter un HMAC (Encrypt-then-MAC).

---

## 5. Ancrage TribuZen

TribuZen stocke des **données sensibles de mineurs** (santé, allergies, traitements, notes internes). La confidentialité **au repos** n'est pas optionnelle : une fuite de base ne doit **pas** exposer ces informations en clair. C'est un enjeu RGPD (données de santé = catégorie particulière) autant que sécurité.

Où ça vit dans `smaurier/tribuzen` (back-office NestJS) :

```
tribuzen-api/
  src/
    crypto/
      field-crypto.service.ts   ← encrypt/decrypt AES-256-GCM, IV par opération, version de clé
      key-provider.ts           ← charge la DEK (wrappée par KEK au KMS), rotation
    children/
      child-medical.entity.ts   ← champs santé chiffrés au repos (transformer NestJS/Prisma)
    webhooks/
      billing.controller.ts     ← vérif HMAC-SHA256 timingSafeEqual du provider de paiement
    common/
      random.ts                 ← tokens de partage via crypto.randomBytes (jamais Math.random)
```

Points d'ancrage concrets :
- **Champs médicaux** : chiffrés en base via AES-256-GCM, DEK wrappée par une KEK au KMS, format `version:iv:ct:tag`.
- **Liens de partage** de fiche (animateur) : token 32 octets **CSPRNG**, à usage unique et TTL court (cf. reset password, module 03).
- **Webhooks paiement** : signature vérifiée en HMAC temps constant avant tout traitement.
- **Transport** : TLS 1.3 partout ; jamais `rejectUnauthorized: false`. Les headers HSTS/CSP → **module 06**. Les secrets d'infra (KMS, vaults) → **module 10**.
- **Mots de passe parents** : **hachés** (argon2id), pas chiffrés → **module 03**.

---

## 6. Points clés

1. **Encodage** (Base64) = zéro sécurité ; **hachage** = intégrité/irréversible ; **chiffrement** = confidentialité réversible avec clé. Ne pas les confondre.
2. Un **mot de passe se hache** (module 03), une **donnée métier se chiffre** ; chiffrer un mot de passe est une faute.
3. **Symétrique = AES-256-GCM** (chiffrement authentifié) pour les volumes ; jamais **ECB**, jamais AES sans mode authentifié.
4. **IV/nonce : 12 octets, unique par opération (CSPRNG), non secret, stocké à côté** ; le rejouer avec la même clé casse GCM.
5. **Asymétrique** = paire publique/privée pour échange de clé et signatures ; **ECC (Curve25519/P-256) préféré à RSA** (RSA ≥ 2048 avec OAEP si utilisé).
6. **HMAC** authentifie un message (webhook) ; comparer en **temps constant** (`timingSafeEqual`), jamais `===`.
7. **TLS 1.3** protège en transit (forward secrecy) ; minimum TLS 1.2, ne jamais désactiver la vérif de certificat.
8. **Clés hors du code** (KEK/DEK, KMS), **rotation** prévue dès le format (version de clé) ; aléa via **CSPRNG**, jamais `Math.random`.
9. **Ne roule jamais ta propre crypto** : `node:crypto` / Web Crypto / `libsodium`, pas d'algo maison.

---

## 7. Seeds Anki

```
Différence entre encodage, hachage et chiffrement ?|Encodage (Base64) : réversible SANS clé, zéro sécurité. Hachage (SHA-256) : sens unique, intégrité. Chiffrement (AES) : réversible AVEC la clé, confidentialité.
Pourquoi ne jamais chiffrer un mot de passe ?|Un mot de passe se HACHE (argon2id, irréversible). Le chiffrer le rend réversible : si la clé fuit, tous les mots de passe redeviennent lisibles. Le chiffrement est pour les données qu'on doit relire.
Quel algorithme/mode symétrique choisir par défaut et lequel proscrire ?|Défaut : AES-256-GCM (chiffrement authentifié = confidentialité + intégrité). Proscrit : ECB (blocs indépendants, motifs du clair visibles).
Règles de l'IV/nonce en AES-GCM ?|12 octets (96 bits), UNIQUE par opération, généré par CSPRNG, non secret (stocké à côté du chiffré). Le réutiliser avec la même clé casse GCM.
RSA vs ECC : lequel préférer aujourd'hui et pourquoi ?|ECC (Curve25519/P-256) : même sécurité que RSA pour des clés bien plus petites et des opérations plus rapides. RSA gardé pour l'interop (≥ 2048 bits, padding OAEP).
Pourquoi comparer un HMAC/token avec timingSafeEqual et pas === ?|=== s'arrête au premier octet différent : le temps de réponse fuit combien d'octets étaient corrects (timing attack). timingSafeEqual compare en temps constant.
Pourquoi Math.random() est interdit en sécurité ?|Ce n'est pas un CSPRNG : ses sorties sont prévisibles. Pour token/IV/sel/clé, utiliser crypto.randomBytes (Node) ou crypto.getRandomValues (navigateur).
Qu'apporte TLS 1.3 par rapport à 1.2 ?|Handshake 1-RTT (plus rapide), suppression des algos obsolètes (RC4/3DES/SHA-1) et forward secrecy obligatoire (compromettre la clé serveur ne déchiffre pas les sessions passées).
Que signifie KEK/DEK en gestion de clés ?|DEK (Data Encryption Key) chiffre les données ; KEK (Key Encryption Key) chiffre la DEK et vit dans un KMS/vault. Clés hors du code/base, rotation prévue via une version de clé.
La règle d'or de la crypto appliquée ?|Ne jamais rouler sa propre crypto : utiliser des primitives éprouvées et auditées (node:crypto, Web Crypto, libsodium, jose), jamais un algo maison "qui a l'air aléatoire".
```

---

## Pont vers le lab

> Lab associé : `labs/lab-05-cryptographie/README.md`. Exercice **défensif** : corriger un module de chiffrement TribuZen fragile (clé en dur + ECB + pas de tag + `Math.random`) pour le porter en AES-256-GCM avec IV unique, tag d'authentification, clé hors du code et tokens CSPRNG — en `node:crypto` puis en Web Crypto. Vrai outil, pas de harnais simulé. Corrigé commenté + variante J+30.
