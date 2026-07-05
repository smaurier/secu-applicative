---
titre: WebAuthn et passkeys (FIDO2) — authentification résistante au phishing
cours: 14-securite-applicative
notions: ["WebAuthn / FIDO2", "passkey", "authenticateur (platform / roaming)", "cérémonie registration", "cérémonie authentication", "challenge à usage unique", "credential id", "clé publique / clé privée", "attestation vs assertion", "origin binding (résistance phishing)", "user verification (biométrie / PIN)", "discoverable credential (resident key)", "signature counter (anti-replay)", "passkey synchronisée vs device-bound", "backup eligibility / backup state"]
outcomes:
  - sait décrire les deux cérémonies WebAuthn (registration et authentication) et ce que chaque étape prouve
  - sait expliquer pourquoi une passkey est résistante au phishing (origin binding, pas de secret partagé)
  - sait distinguer attestation et assertion, credential id, clé publique stockée serveur et clé privée jamais exportée
  - sait choisir entre passkey synchronisée et device-bound selon le niveau de sensibilité des données
  - sait concevoir une stratégie de vérification serveur (challenge unique, expectedOrigin, expectedRPID, counter) et un fallback de récupération
prerequis: [Module 00 posture et modèle de menace, Module 01 OWASP Top 10, Module 02 injection, Module 03 authentification (sessions / hachage / MFA), Module 03b OIDC-PKCE côté client]
next: 04-autorisation
libs: []
tribuzen: couche authentification TribuZen — passkeys pour le login parent sans mot de passe, en complément de la session applicative
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# WebAuthn et passkeys (FIDO2) — authentification résistante au phishing

> **Outcomes — tu sauras FAIRE :** décrire les deux cérémonies WebAuthn, expliquer la résistance au phishing par origin binding, distinguer attestation/assertion et passkey synchronisée/device-bound, concevoir la vérification serveur et un fallback de récupération.
> **Difficulté :** :star::star::star:
>
> **Portée :** ce module couvre le **modèle WebAuthn** (cérémonies, credential, vérifications) du point de vue **défensif** : comprendre ce qui rend une passkey sûre et ce que le serveur DOIT vérifier. La cryptographie sous-jacente (signatures asymétriques, courbes) est approfondie au **module 05**. Le durcissement des cookies/sessions émis après login est au **module 06**. Ce module montre les vulnérabilités du mot de passe **pour les corriger**, jamais pour les exploiter.

## 1. Cas concret d'abord

TribuZen stocke des données de famille sensibles : santé des enfants, adresses, agendas. Le login actuel est email + mot de passe. Un parent reçoit ce mail :

```
De : securite@tribuzen-support.fr        ← domaine PROCHE mais FAUX
Objet : Vérifiez votre compte famille

Nous avons détecté une connexion inhabituelle.
Confirmez votre identité : https://tribuzen-support.fr/login
```

Le parent clique, voit une page identique au vrai TribuZen, tape son email et son mot de passe. **L'attaquant a maintenant les identifiants.** Le MFA par SMS ou TOTP ne sauve pas toujours : un phishing en temps réel (reverse proxy type Evilginx) capture aussi le code à 6 chiffres et le rejoue immédiatement sur le vrai site.

Le problème de fond : **un mot de passe (et un OTP) est un secret partagé que l'utilisateur peut donner au mauvais site.** Tant que l'humain est capable de recopier le secret ailleurs, le phishing reste possible.

La question du module : **comment concevoir une authentification où l'utilisateur ne PEUT PAS livrer son secret à un faux site, même en cliquant sur le lien ?** Réponse : WebAuthn / passkeys. La clé privée ne quitte jamais l'appareil, et le navigateur refuse de l'utiliser sur un domaine qui ne correspond pas à celui de l'enregistrement. Le phishing du cas ci-dessus échoue **par construction** : la passkey enregistrée sur `tribuzen.fr` est inutilisable sur `tribuzen-support.fr`.

---

## 2. Théorie complète, concise

### 2.1 Le modèle : paire de clés, pas de secret partagé

WebAuthn (spec W3C, la couche navigateur de **FIDO2** — l'autre couche étant CTAP entre navigateur et authenticateur) remplace le secret partagé par une **paire de clés asymétrique** par site :

- **Clé privée** — générée et gardée par l'**authenticateur** (Secure Enclave iOS, TPM Windows, clé Titan/YubiKey...). Elle **ne quitte jamais** l'appareil sous forme utilisable, et n'est **jamais** envoyée au serveur.
- **Clé publique** — envoyée au serveur à l'enregistrement, stockée en base. Publique = sa fuite ne compromet rien : on ne peut pas forger une signature avec elle.

S'authentifier = **signer un défi** (challenge) du serveur avec la clé privée. Le serveur vérifie la signature avec la clé publique. Aucun secret ne transite ni n'est stockable côté serveur : une fuite de la base ne donne que des clés publiques, inexploitables.

Vocabulaire :

| Terme | Sens |
|-------|------|
| **Relying Party (RP)** | le site qui authentifie (TribuZen). Identifié par le `rp.id` (un domaine, ex. `tribuzen.fr`). |
| **Authenticateur** | le composant matériel/logiciel qui garde la clé privée et fait la signature. |
| **Passkey** | une credential WebAuthn **discoverable** (voir 2.5), utilisable sans taper d'identifiant. |
| **Credential id** | identifiant de la paire de clés, généré par l'authenticateur, stocké côté serveur pour retrouver la bonne clé publique. |
| **Challenge** | octets aléatoires générés par le serveur, à **usage unique**, pour empêcher le rejeu. |
| **User verification (UV)** | preuve de présence + identité locale (biométrie Face ID / Touch ID / Windows Hello ou PIN) faite **sur l'appareil**, jamais transmise. |

### 2.2 Deux cérémonies

WebAuthn définit deux « cérémonies ». Chacune suit le même pattern : le serveur lance un défi, l'appareil répond, le serveur vérifie.

**Registration (enregistrement)** — associer une nouvelle passkey à un compte :

```
Client (navigateur)                       Serveur (RP)
   │                                          │
   │──── demande d'enregistrement ───────────►│
   │                                          │ génère options :
   │                                          │  challenge (aléatoire, stocké)
   │◄──── PublicKeyCredentialCreationOptions ─│  rp, user, pubKeyCredParams…
   │                                          │
   │ navigator.credentials.create({publicKey})│
   │  → user verification (Face ID / PIN)     │
   │  → l'authenticateur crée la paire de clés│
   │  → renvoie une ATTESTATION               │
   │                                          │
   │──── PublicKeyCredential (attestation) ──►│ vérifie : origin, rpId,
   │                                          │  challenge attendu, signature
   │◄──── { verified: true } ─────────────────│ stocke clé publique + credId + counter
```

**Authentication (connexion)** — prouver la possession d'une passkey déjà enregistrée :

```
Client (navigateur)                       Serveur (RP)
   │                                          │
   │──── demande de connexion ───────────────►│
   │                                          │ génère un NOUVEAU challenge
   │◄──── PublicKeyCredentialRequestOptions ──│  (+ allowCredentials éventuel)
   │                                          │
   │ navigator.credentials.get({publicKey})   │
   │  → user verification (Face ID / PIN)     │
   │  → la clé privée SIGNE le challenge       │
   │  → renvoie une ASSERTION                  │
   │                                          │
   │──── PublicKeyCredential (assertion) ────►│ vérifie signature avec la clé
   │                                          │  publique stockée, origin, rpId,
   │                                          │  challenge, counter
   │◄──── session / JWT ──────────────────────│ (login réussi)
```

Note importante : WebAuthn **remplace le login**, pas la session. Après une authentication réussie, tu émets une session/JWT classique (voir modules 03 et 06 pour le durcissement des cookies).

### 2.3 Attestation vs assertion — ne pas confondre

- **Attestation** = sortie de `create()` (registration). Elle prouve **d'où vient** la credential : quel type/modèle d'authenticateur a créé la clé. Objet `AuthenticatorAttestationResponse` (`clientDataJSON` + `attestationObject`). L'attestation *forte* (`direct`) n'est utile qu'en contexte entreprise/réglementé où l'on veut restreindre les modèles d'authenticateurs. Pour un produit grand public comme TribuZen, `attestation: "none"` est la norme (moins de friction, pas de traçage de l'appareil).
- **Assertion** = sortie de `get()` (authentication). Elle prouve la **possession** de la clé privée : c'est la signature du challenge. Objet `AuthenticatorAssertionResponse` (`clientDataJSON` + `authenticatorData` + `signature` + `userHandle`).

Moyen mnémotechnique : **A**ttestation à la naissance de la clé (registration), **A**ssertion à chaque usage (authentication).

### 2.4 Origin binding — le cœur de la résistance au phishing

C'est LA propriété à retenir. Deux verrous cumulés :

1. **Le navigateur lie la credential à l'origine.** À la création, l'authenticateur enregistre la clé pour un `rp.id` (domaine). Le navigateur **refuse** d'utiliser cette clé sur une autre origine. Une passkey `tribuzen.fr` ne se déclenche jamais sur `tribuzen-support.fr` — l'utilisateur ne verra même pas l'invite. Le secret ne peut **pas** être « recopié » sur un faux site, contrairement à un mot de passe ou un OTP.
2. **Le serveur revérifie l'origine.** Le `clientDataJSON` signé contient l'`origin` réelle et le `challenge`. Le serveur vérifie `expectedOrigin` et `expectedRPID`. Même si un attaquant tentait de rejouer une réponse, l'origin signée ne correspondrait pas.

C'est pourquoi WebAuthn est qualifié de **phishing-resistant** : la résistance n'est pas dans la vigilance de l'humain, elle est **structurelle**.

### 2.5 Discoverable credential (resident key) = passkey

Historiquement, deux formes de credentials :

- **Non-discoverable** (`residentKey: "discouraged"`) : la clé privée n'est pas stockée dans l'authenticateur ; le serveur doit fournir la liste des `credential id` (`allowCredentials`) pour que l'appareil retrouve la bonne clé. L'utilisateur doit d'abord dire QUI il est (email).
- **Discoverable** (`residentKey: "required"`) : l'authenticateur stocke la credential ET l'identité (userHandle, nom). L'utilisateur peut se connecter **sans taper d'identifiant** — le navigateur propose ses passkeys. **C'est ce qu'on appelle une passkey.**

Pour l'UX « usernameless » (autofill), on utilise la **conditional mediation** : `navigator.credentials.get({ publicKey, mediation: "conditional" })` avec un champ `<input autocomplete="username webauthn">`. À tester via `PublicKeyCredential.isConditionalMediationAvailable()`.

### 2.6 User verification et anti-replay (counter)

- **User verification (UV)** : la biométrie/PIN se fait **localement** sur l'appareil ; elle débloque l'usage de la clé privée mais n'est **jamais** transmise au serveur. Pour des données sensibles (TribuZen), on veut `userVerification: "required"` — cela transforme la passkey en facteur *fort* (possession de l'appareil + biométrie/PIN).
- **Signature counter** : `authenticatorData` peut contenir un compteur qui s'incrémente à chaque signature. Le serveur le stocke et vérifie qu'il **augmente** à chaque connexion. S'il **régresse ou stagne**, cela peut trahir une credential clonée (replay) → alerter/révoquer. Beaucoup d'authenticateurs synchronisés renvoient un counter à 0 (pas de compteur) : dans ce cas la vérification est neutralisée, ce qui est un compromis accepté du modèle synchronisé.

### 2.7 Passkey synchronisée vs device-bound

Distinction majeure côté produit (source : FIDO Alliance, 2025) :

| | **Synchronisée (synced)** | **Device-bound** |
|---|---|---|
| Où vit la clé privée | dans un gestionnaire (iCloud Keychain, Google Password Manager, 1Password…), **répliquée** sur les appareils du même compte | **enfermée** dans un seul authenticateur (souvent une clé matérielle type YubiKey) ; non exportable |
| Récupération après perte d'appareil | automatique : la passkey réapparaît sur un autre appareil du même compte | aucune : perdre l'appareil = perdre la clé → besoin d'un autre facteur d'enrôlement |
| Sécurité du stockage | dépend de la sécurité du compte cloud de synchronisation | la plus forte (jamais copiée) |
| Cas d'usage | grand public, priorité à l'UX et à la récupération | entreprise/haute assurance, exigence de non-copie |

Signal technique : à l'enregistrement, l'`authenticatorData` porte deux drapeaux — **Backup Eligibility (BE)** « la clé PEUT être sauvegardée/synchronisée » et **Backup State (BS)** « la clé EST actuellement sauvegardée ». Les bibliothèques serveur les exposent souvent sous `credentialDeviceType` (`singleDevice` / `multiDevice`) et `credentialBackedUp` (booléen). **Le RP ne peut pas empêcher la synchronisation** d'une passkey synced : il ne fait que la constater via BE/BS et adapter sa politique (ex. exiger une clé matérielle device-bound pour un rôle admin).

### 2.8 Ce que le serveur DOIT vérifier (checklist défensive)

La sécurité de WebAuthn tient à la vérification serveur. À la registration ET à l'authentication :

1. **Challenge** = exactement celui émis, à **usage unique**, non expiré → puis supprimé.
2. **Origin** signée == `expectedOrigin` (`https://tribuzen.fr`).
3. **rpIdHash** == hash de `expectedRPID` (`tribuzen.fr`).
4. **User verification flag** présent si `userVerification: "required"`.
5. (auth) **Signature** valide contre la clé publique stockée pour ce `credential id`.
6. (auth) **Counter** croissant (si non nul).

Ne **jamais** implémenter ces vérifications cryptographiques à la main : utiliser une bibliothèque serveur maintenue et à jour, et lui passer `expectedOrigin`/`expectedRPID`/`expectedChallenge` explicites.

---

## 3. Worked examples

### Exemple 1 — Client : registration puis authentication (Web Authentication API native)

Voici les deux appels navigateur, côté TribuZen. Le serveur fournit les *options* (challenge inclus) ; on convertit les champs base64url en `ArrayBuffer` car l'API attend des octets binaires.

```ts
// src/features/auth/passkey-client.ts

// Support minimal : platform authenticator (Face ID / Windows Hello) disponible ?
async function passkeysDisponibles(): Promise<boolean> {
  if (!window.PublicKeyCredential) return false
  return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
}

// --- REGISTRATION : navigator.credentials.create() ---
export async function enregistrerPasskey(): Promise<void> {
  // 1. Le serveur génère et renvoie les options (challenge à usage unique inclus)
  const options = await fetch('/api/auth/passkey/register/start', {
    method: 'POST',
    credentials: 'include',
  }).then((r) => r.json())

  // 2. Décoder challenge + user.id (base64url -> ArrayBuffer)
  options.challenge = base64urlToBuffer(options.challenge)
  options.user.id = base64urlToBuffer(options.user.id)

  // 3. Déclenche l'UI native de l'OS (biométrie) et crée la paire de clés
  let credential: PublicKeyCredential
  try {
    credential = (await navigator.credentials.create({
      publicKey: options as PublicKeyCredentialCreationOptions,
    })) as PublicKeyCredential
  } catch (e) {
    // InvalidStateError = une passkey existe déjà pour cet authenticateur
    if (e instanceof DOMException && e.name === 'InvalidStateError') {
      throw new Error('Une passkey existe déjà sur cet appareil.')
    }
    // NotAllowedError = annulation utilisateur ou délai dépassé
    throw new Error("Enregistrement annulé.")
  }

  // 4. Renvoyer l'ATTESTATION au serveur pour vérification + stockage clé publique
  const ok = await fetch('/api/auth/passkey/register/finish', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    // credential.toJSON() sérialise proprement l'attestation (méthode standard)
    body: JSON.stringify(credential.toJSON()),
  })
  if (!ok.ok) throw new Error("Vérification serveur échouée.")
}

// --- AUTHENTICATION : navigator.credentials.get() ---
export async function seConnecterAvecPasskey(): Promise<void> {
  // 1. Nouveau challenge du serveur ; allowCredentials vide => passkey discoverable
  const options = await fetch('/api/auth/passkey/login/start', {
    method: 'POST',
  }).then((r) => r.json())
  options.challenge = base64urlToBuffer(options.challenge)

  // 2. L'utilisateur choisit sa passkey + user verification ; la clé privée SIGNE
  const assertion = (await navigator.credentials.get({
    publicKey: options as PublicKeyCredentialRequestOptions,
  })) as PublicKeyCredential

  // 3. Envoyer l'ASSERTION ; le serveur vérifie la signature et ouvre la session
  const res = await fetch('/api/auth/passkey/login/finish', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(assertion.toJSON()),
  })
  if (!res.ok) throw new Error('Authentification échouée.')
}
```

Points clés du client : il ne fait **que** transporter des options et une réponse signée. Tout ce qui protège (challenge, origin, signature) est **produit et vérifié ailleurs** — l'appareil et le serveur. Un client compromis ne peut pas fabriquer une signature valide sans la clé privée.

### Exemple 2 — Serveur : génération d'options et vérification (schéma défensif)

Côté serveur (NestJS chez TribuZen), on **délègue la crypto à une bibliothèque WebAuthn** et on se concentre sur les invariants défensifs. Pseudocode volontairement lib-agnostique :

```ts
// REGISTRATION — start : produire des options sûres
function registerStart(user: User) {
  const options = webauthn.generateRegistrationOptions({
    rpName: 'TribuZen',
    rpID: 'tribuzen.fr',              // == domaine, sinon origin binding cassé
    userName: user.email,
    // Passkey discoverable + biométrie/PIN obligatoire pour données famille
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
    },
    // Empêche de réenregistrer un authenticateur déjà lié à ce compte
    excludeCredentials: user.passkeys.map((p) => ({ id: p.credentialId })),
  })
  // Le challenge est stocké côté serveur, à USAGE UNIQUE, TTL court (ex. 5 min)
  challengeStore.set(user.id, options.challenge, { ttlSeconds: 300 })
  return options
}

// REGISTRATION — finish : vérifier avant de stocker la clé publique
async function registerFinish(user: User, body: unknown) {
  const expectedChallenge = challengeStore.take(user.id) // take = lit ET supprime
  if (!expectedChallenge) throw new Unauthorized('Challenge expiré.')

  const result = await webauthn.verifyRegistrationResponse({
    response: body,
    expectedChallenge,
    expectedOrigin: 'https://tribuzen.fr',  // verrou anti-phishing #2
    expectedRPID: 'tribuzen.fr',
    requireUserVerification: true,
  })
  if (!result.verified) throw new Unauthorized('Attestation invalide.')

  const { credentialID, credentialPublicKey, counter,
          credentialDeviceType, credentialBackedUp } = result.registrationInfo
  await passkeyRepo.save({
    userId: user.id,
    credentialId: credentialID,       // sert de clé de recherche à l'auth
    publicKey: credentialPublicKey,   // publique -> stockage en base OK
    counter,                          // base de l'anti-replay
    deviceType: credentialDeviceType, // 'singleDevice' | 'multiDevice'
    backedUp: credentialBackedUp,     // true = passkey synchronisée (BE/BS)
  })
}

// AUTHENTICATION — finish : vérifier la signature + faire avancer le counter
async function loginFinish(body: { id: string }) {
  const passkey = await passkeyRepo.findByCredentialId(body.id)
  if (!passkey) throw new Unauthorized('Credential inconnue.')

  const expectedChallenge = challengeStore.take(passkey.userId)
  const result = await webauthn.verifyAuthenticationResponse({
    response: body,
    expectedChallenge,
    expectedOrigin: 'https://tribuzen.fr',
    expectedRPID: 'tribuzen.fr',
    requireUserVerification: true,
    credential: {
      id: passkey.credentialId,
      publicKey: passkey.publicKey,
      counter: passkey.counter,
    },
  })
  if (!result.verified) throw new Unauthorized('Signature invalide.')

  // Anti-replay : le counter DOIT progresser (si l'authenticateur en fournit un)
  await passkeyRepo.updateCounter(passkey.id, result.authenticationInfo.newCounter)

  // Login réussi -> émettre la session/JWT (durcissement cookies : module 06)
  return session.issueFor(passkey.userId)
}
```

Ce qui rend ce code défensif : challenge **pris-et-supprimé** (usage unique), `expectedOrigin`/`expectedRPID` **explicites** (jamais dérivés de la requête entrante), `requireUserVerification`, et **avancée du counter**. La crypto n'est pas réimplémentée.

---

## 4. Pièges & misconceptions

### PIÈGE #1 — « La passkey remplace la session / le MFA à tous les étages »

Faux. WebAuthn remplace **l'acte de login**. Après une authentication réussie, tu émets une session/JWT normale — avec toutes les protections habituelles (cookie `HttpOnly` + `Secure` + `SameSite`, expiration : module 06). Une passkey ne dispense pas de sécuriser ce qui vient après le login.

### PIÈGE #2 — « Passkey = pas de phishing possible, donc rien d'autre à vérifier »

La résistance au phishing tient **uniquement** si le serveur vérifie `expectedOrigin` et `expectedRPID`. Un serveur qui accepte n'importe quelle origine, ou qui dérive le `rpID` du `Host` de la requête, casse le verrou #2. L'origin binding navigateur seul ne suffit pas si le backend est laxiste.

### PIÈGE #3 — Réutiliser un challenge

Un challenge est à **usage unique** et à durée de vie courte. Le laisser en base sans le supprimer après vérification, ou le partager entre requêtes, rouvre la porte au rejeu. Pattern correct : `take()` (lire **et** supprimer atomiquement), TTL court.

### PIÈGE #4 — Confondre attestation et assertion

`create()` → **attestation** (preuve d'origine de la clé, à la registration). `get()` → **assertion** (preuve de possession, signature, à chaque login). Passer un objet d'attestation à `verifyAuthenticationResponse` (ou l'inverse) est une erreur classique. Voir 2.3.

### PIÈGE #5 — `rp.id` ≠ domaine réel

Le `rp.id` doit être le domaine enregistrable du site (`tribuzen.fr`), pas une URL, pas un sous-chemin, pas un port. S'il ne correspond pas à l'origine où l'utilisateur navigue (règle des sous-domaines incluse), le navigateur **rejette** l'appel. Symptôme typique : `SecurityError` ou invite qui ne s'affiche jamais. Une passkey enregistrée avec le mauvais `rp.id` est inutilisable.

### PIÈGE #6 — Croire que le RP peut interdire la synchronisation

Un RP **ne contrôle pas** si une passkey grand public est synchronisée : le gestionnaire (iCloud/Google) décide. Le RP ne fait que **lire** les drapeaux BE/BS (`backedUp`) et ajuster sa politique (ex. exiger un authenticateur device-bound pour un rôle sensible via `authenticatorAttachment: "cross-platform"`). Concevoir une politique en supposant l'inverse est un piège.

### PIÈGE #7 — Oublier le fallback de récupération

Une passkey device-bound perdue = accès perdu s'il n'existe aucune autre voie. Toujours prévoir : au moins **deux** passkeys enregistrées, ou une passkey synchronisée, ou un chemin de récupération (email vérifié + facteur secondaire). Sans ça, une perte d'appareil devient un lockout définitif — inacceptable pour un parent qui gère les données de sa famille.

---

## 5. Ancrage TribuZen

TribuZen manipule des données famille sensibles : le phishing d'un compte parent est un risque à fort impact (RGPD, données d'enfants). WebAuthn est donc la cible d'authentification.

**Où ça vit dans le produit :**

```
tribuzen/
  apps/api/src/auth/
    passkey.controller.ts      ← /register/start|finish, /login/start|finish
    passkey.service.ts         ← generate/verify options (lib WebAuthn)
    challenge.store.ts         ← challenges à usage unique, TTL court
  apps/web/src/features/auth/
    passkey-client.ts          ← Exemple 1 (create / get)
    LoginPasskeyButton.vue     ← bouton + conditional mediation
```

**Politique TribuZen retenue :**

- **Login parent** : passkey **synchronisée**, `userVerification: "required"`. Priorité à la récupération (un parent qui change de téléphone ne doit pas perdre l'accès aux données famille) — la passkey réapparaît via iCloud/Google.
- **Rôle admin/gestion de facturation** : proposer en plus une passkey **device-bound** (clé matérielle) comme second facteur d'enrôlement, pour les comptes à privilèges élevés (lien avec le module 04 — autorisation et moindre privilège).
- **Fallback** : chaque compte doit avoir **au moins deux** moyens (2 passkeys, ou 1 passkey + email vérifié + code à usage unique). Communiqué clairement à l'onboarding.
- **Données ultra-sensibles device-only (chiffrées de bout en bout)** : par design, non récupérables si tous les appareils sont perdus — l'afficher honnêtement (« ces données ne quittent jamais vos appareils, c'est votre protection »).

Le résultat concret : le mail de phishing du §1 devient inoffensif. Même si le parent clique et arrive sur `tribuzen-support.fr`, aucune passkey ne se déclenche, il n'a **rien** à taper qui puisse fuiter.

---

## 6. Points clés

1. WebAuthn/FIDO2 remplace le secret partagé par une **paire de clés par site** : clé privée jamais exportée, clé publique stockée serveur.
2. **Deux cérémonies** : registration (`create()` → attestation) et authentication (`get()` → assertion), même pattern challenge/réponse/vérification.
3. La **résistance au phishing** est structurelle : origin binding navigateur **+** vérification `expectedOrigin`/`expectedRPID` serveur. Les deux sont nécessaires.
4. **Attestation** = origine de la clé (registration) ; **assertion** = possession/signature (authentication). Ne pas confondre.
5. Une **passkey** = credential **discoverable** (`residentKey: "required"`), login possible sans identifiant (conditional mediation).
6. Le **challenge** est à usage unique + TTL court ; le **counter** doit progresser (anti-replay) quand l'authenticateur en fournit un.
7. **Synchronisée vs device-bound** : synced = récupérable, priorité UX ; device-bound = non copiable, haute assurance. Le RP lit BE/BS (`backedUp`) mais ne contrôle pas la synchro.
8. WebAuthn remplace le **login**, pas la session ni le fallback : durcir les cookies (module 06) et toujours prévoir une récupération.

---

## 7. Seeds Anki

```
Pourquoi une passkey résiste-t-elle au phishing là où un mot de passe + OTP échoue ?|La clé privée ne quitte jamais l'appareil et le navigateur refuse de l'utiliser sur une autre origine (origin binding). L'utilisateur n'a aucun secret recopiable à livrer à un faux site ; le serveur revérifie expectedOrigin/expectedRPID.
Quelle méthode navigateur pour la registration et laquelle pour l'authentication WebAuthn ?|Registration = navigator.credentials.create({publicKey}) qui renvoie une attestation. Authentication = navigator.credentials.get({publicKey}) qui renvoie une assertion (signature du challenge).
Attestation vs assertion en WebAuthn ?|Attestation = preuve d'ORIGINE de la clé, produite à la registration (create). Assertion = preuve de POSSESSION, signature du challenge produite à chaque authentication (get).
Qu'est-ce qu'une passkey (credential discoverable / resident key) ?|Une credential où l'authenticateur stocke la clé ET l'identité (userHandle) => login sans taper d'identifiant. residentKey: "required". Permet l'autofill via conditional mediation.
Que DOIT vérifier le serveur à chaque cérémonie WebAuthn ?|Challenge attendu à usage unique et non expiré, expectedOrigin, expectedRPID, flag user verification si requis, (auth) signature valide contre la clé publique et counter croissant.
Différence passkey synchronisée vs device-bound ?|Synchronisée : clé répliquée dans un gestionnaire (iCloud/Google), récupérable après perte d'appareil, priorité UX. Device-bound : clé enfermée dans un seul authenticateur, non exportable, haute assurance mais aucune récupération native.
À quoi sert le signature counter et que signale sa régression ?|Il s'incrémente à chaque signature ; le serveur vérifie qu'il progresse. S'il régresse ou stagne (quand non nul), cela peut trahir une credential clonée (replay) => alerter/révoquer.
WebAuthn remplace-t-il la session applicative ?|Non. Il remplace l'acte de login. Après une authentication réussie, on émet une session/JWT normale à durcir (cookie HttpOnly + Secure + SameSite, expiration).
```

---

## Pont vers le lab

> Lab associé : `labs/lab-03c-webauthn-passkeys/README.md`. Exercice **défensif** : concevoir un flux WebAuthn registration + authentication pour TribuZen, spécifier les vérifications serveur, gérer le stockage des credentials et le fallback de récupération. README-only, corrigé raisonné, variante J+30.
