# Module 3c — WebAuthn / Passkeys : supprimer les mots de passe

| Difficulté | Durée estimée |
|------------|---------------|
| 3/5        | 75 min        |

> **Prérequis** : Module 03 (Authentification) + Module 03b (OIDC/PKCE). Tu dois comprendre JWT et le flow OAuth2 avant d'aborder WebAuthn.

## Objectifs

- Comprendre ce que sont les passkeys (FIDO2 / WebAuthn W3C)
- Implémenter la cérémonie d'enregistrement (registration)
- Implémenter la cérémonie d'authentification (authentication)
- Valider les assertions côté serveur (NestJS)
- Gérer le stockage OS Keychain (iCloud / Google Password Manager)
- Comprendre la récupération sans mot de passe de secours

---

## Pourquoi les mots de passe sont morts

```
Problème mot de passe :
  ├── Phishing      → l'utilisateur entre ses credentials sur un faux site
  ├── Brute force   → si le mot de passe est faible
  ├── Data breach   → si la base de données est volée (même hashé = risque)
  ├── Réutilisation → 65% des utilisateurs réutilisent le même mdp (Google 2019)
  └── Oubli         → "Mot de passe oublié" = friction = abandon

Solution passkey :
  ├── Credential = paire de clés (privée / publique)
  ├── Clé privée → stockée dans l'OS Keychain (iCloud / Google / Windows Hello)
  ├── Clé publique → stockée sur le serveur
  ├── Authentification = signature cryptographique du challenge serveur
  └── Phishing impossible → les clés sont liées au domaine (origin binding)
```

**Chiffre clé** : passkeys suppriment 100% du risque phishing lié aux credentials (FIDO Alliance, 2023). La clé privée ne quitte jamais l'appareil.

---

## Les deux cérémonies WebAuthn

### Cérémonie 1 — Enregistrement (Registration)

```
Client (navigateur)              Serveur
      │                              │
      │── POST /auth/register/start ─►│
      │                              │ génère registrationOptions
      │◄── registrationOptions ──────│ (challenge, rpId, userId...)
      │                              │
      │ navigator.credentials.create()
      │ → OS Keychain crée la paire de clés
      │ → clé privée stockée dans Keychain
      │ → credential contient clé publique + attestation
      │                              │
      │── POST /auth/register/finish ─►│
      │   (credential JSON)          │ vérifie attestation
      │                              │ stocke clé publique en base
      │◄── { success: true } ────────│
```

### Cérémonie 2 — Authentification

```
Client (navigateur)              Serveur
      │                              │
      │── POST /auth/login/start ───►│
      │                              │ génère authenticationOptions
      │◄── authenticationOptions ────│ (challenge, allowCredentials...)
      │                              │
      │ navigator.credentials.get()
      │ → Face ID / Touch ID / PIN
      │ → clé privée signe le challenge
      │ → assertion contient la signature
      │                              │
      │── POST /auth/login/finish ──►│
      │   (assertion JSON)           │ vérifie signature avec clé publique
      │                              │ → si OK : émet JWT/session
      │◄── { token: "..." } ─────────│
```

---

## Implémentation complète

### Dépendances

```bash
# Backend NestJS
npm install @simplewebauthn/server

# Frontend React
npm install @simplewebauthn/browser
```

### Backend NestJS — Enregistrement

```typescript
// src/auth/webauthn.service.ts
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';

@Injectable()
export class WebAuthnService {
  private readonly rpName = 'TribuZen';
  private readonly rpID = 'tribuzen.fr'; // doit correspondre exactement au domaine
  private readonly origin = 'https://tribuzen.fr';

  async generateRegistrationOptions(user: User) {
    const options = await generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.rpID,
      userID: isoUint8Array.fromUTF8String(user.id),
      userName: user.email,
      userDisplayName: user.name,
      // Empêche la réenregistrement du même authenticator
      excludeCredentials: user.passkeys.map((pk) => ({
        id: pk.credentialId,
        type: 'public-key',
      })),
      authenticatorSelection: {
        // Passkey = credential découvrable (stocké dans le Keychain, pas juste sur l'authenticator)
        residentKey: 'required',
        userVerification: 'required', // Face ID / Touch ID / PIN obligatoire
      },
    });

    // Stocker le challenge en session (vérifié au finish)
    await this.cacheService.set(`reg_challenge_${user.id}`, options.challenge, 300);

    return options;
  }

  async verifyRegistration(user: User, response: RegistrationResponseJSON) {
    const expectedChallenge = await this.cacheService.get(`reg_challenge_${user.id}`);
    if (!expectedChallenge) throw new Error('Challenge expired or not found');

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: this.origin,
      expectedRPID: this.rpID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw new Error('Registration verification failed');
    }

    const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

    // Stocker la clé publique en base
    await this.passkeyRepository.create({
      userId: user.id,
      credentialId: isoBase64URL.fromBuffer(credentialID),
      publicKey: isoBase64URL.fromBuffer(credentialPublicKey),
      counter,
      deviceType: verification.registrationInfo.credentialDeviceType,
      backedUp: verification.registrationInfo.credentialBackedUp, // true si synchronisé dans le Keychain
    });

    await this.cacheService.del(`reg_challenge_${user.id}`);
    return { verified: true };
  }
}
```

### Backend NestJS — Authentification

```typescript
// src/auth/webauthn.service.ts (suite)

async generateAuthenticationOptions(email: string) {
  const user = await this.userRepository.findByEmail(email);
  // Note : si residentKey = required, on peut ne PAS envoyer allowCredentials
  // → le navigateur proposera tous les passkeys du domaine (meilleure UX)
  const options = await generateAuthenticationOptions({
    rpID: this.rpID,
    userVerification: 'required',
    allowCredentials: user
      ? user.passkeys.map((pk) => ({
          id: pk.credentialId,
          type: 'public-key',
        }))
      : [], // passkey discoverable → vide = navigateur choisit
  });

  await this.cacheService.set(`auth_challenge_${email}`, options.challenge, 300);
  return options;
}

async verifyAuthentication(email: string, response: AuthenticationResponseJSON) {
  const user = await this.userRepository.findByEmail(email);
  if (!user) throw new UnauthorizedException();

  const expectedChallenge = await this.cacheService.get(`auth_challenge_${email}`);
  if (!expectedChallenge) throw new Error('Challenge expired');

  // Trouver la passkey utilisée
  const passkey = user.passkeys.find(
    (pk) => pk.credentialId === response.id
  );
  if (!passkey) throw new UnauthorizedException('Passkey not found');

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: this.origin,
    expectedRPID: this.rpID,
    authenticator: {
      credentialID: isoBase64URL.toBuffer(passkey.credentialId),
      credentialPublicKey: isoBase64URL.toBuffer(passkey.publicKey),
      counter: passkey.counter,
    },
  });

  if (!verification.verified) throw new UnauthorizedException('Signature invalid');

  // Mettre à jour le counter (protection contre replay attacks)
  await this.passkeyRepository.updateCounter(
    passkey.id,
    verification.authenticationInfo.newCounter
  );

  await this.cacheService.del(`auth_challenge_${email}`);

  // Émettre un JWT classique (passkeys remplacent le login, pas la session)
  return this.authService.generateToken(user);
}
```

### Frontend React — Enregistrement

```typescript
// src/features/auth/register-passkey.ts
import {
  startRegistration,
  browserSupportsWebAuthn,
} from '@simplewebauthn/browser';

export async function registerPasskey(): Promise<void> {
  if (!browserSupportsWebAuthn()) {
    throw new Error('Ton appareil ne supporte pas les passkeys');
  }

  // 1. Obtenir les options du serveur
  const optionsRes = await fetch('/api/auth/register/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
  });
  const options = await optionsRes.json();

  // 2. Déclencher Face ID / Touch ID / Windows Hello
  // → Le navigateur ouvre la UI native de l'OS
  let attResp;
  try {
    attResp = await startRegistration(options);
  } catch (error) {
    if (error.name === 'InvalidStateError') {
      throw new Error('Un passkey existe déjà pour cet appareil');
    }
    if (error.name === 'NotAllowedError') {
      throw new Error('Enregistrement annulé');
    }
    throw error;
  }

  // 3. Envoyer au serveur pour vérification
  const verifyRes = await fetch('/api/auth/register/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(attResp),
    credentials: 'include',
  });

  if (!verifyRes.ok) throw new Error('Enregistrement échoué');
}
```

### Frontend React — Authentification

```typescript
// src/features/auth/login-passkey.ts
import { startAuthentication } from '@simplewebauthn/browser';

export async function loginWithPasskey(email?: string): Promise<string> {
  // 1. Options du serveur (email optionnel si passkey discoverable)
  const optionsRes = await fetch('/api/auth/login/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  const options = await optionsRes.json();

  // 2. Face ID / Touch ID / Windows Hello
  let asserResp;
  try {
    asserResp = await startAuthentication(options);
  } catch (error) {
    if (error.name === 'NotAllowedError') {
      throw new Error('Authentification annulée ou délai expiré');
    }
    throw error;
  }

  // 3. Vérification serveur → JWT
  const verifyRes = await fetch('/api/auth/login/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, assertion: asserResp }),
  });

  if (!verifyRes.ok) throw new Error('Authentification échouée');
  const { token } = await verifyRes.json();
  return token;
}
```

---

## Schéma base de données (Prisma)

```prisma
model Passkey {
  id           String   @id @default(cuid())
  userId       String
  credentialId String   @unique
  publicKey    String   @db.Text
  counter      BigInt   @default(0)
  deviceType   String   // 'singleDevice' | 'multiDevice'
  backedUp     Boolean  @default(false) // true = synchronisé dans iCloud/Google
  createdAt    DateTime @default(now())
  lastUsedAt   DateTime?

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([userId])
}
```

**`backedUp: true`** = la clé est synchronisée dans iCloud Keychain ou Google Password Manager → si l'utilisateur perd son téléphone, la passkey est récupérée automatiquement sur son nouvel appareil.

---

## Stratégie de récupération (TribuZen)

```
Scénario : parent perd son téléphone

backedUp = true (98% des cas sur iOS/Android modernes) :
  → nouvelle connection sur nouvel appareil
  → iCloud / Google restaure automatiquement la passkey
  → aucune action requise de l'utilisateur

backedUp = false (authenticator matériel, rare) :
  → email de récupération + code 8 chiffres OTP
  → accès lecture seule aux données Level 2 et 3
  → données Level 1 (device uniquement, E2EE) = irrécupérables par design
    → afficher clairement dans l'onboarding :
      "Vos données médicales ne quittent jamais votre appareil.
       C'est votre protection. En cas de perte sans backup Keychain,
       seules ces données sont perdues."
```

---

## Compatibilité

| Plateforme | Support |
|-----------|---------|
| iOS 16+ (Safari) | ✅ iCloud Keychain |
| Android 9+ (Chrome) | ✅ Google Password Manager |
| macOS 13+ (Safari / Chrome) | ✅ |
| Windows 11 (Chrome / Edge) | ✅ Windows Hello |
| Firefox | ⚠️ Partiel (2024) |

> **TribuZen** : 95%+ des parents cibles sont sur iOS ou Android récents. Support suffisant pour beta.

---

## Erreurs fréquentes

```typescript
// ❌ Utiliser le même challenge pour plusieurs requêtes
// → Un challenge doit être à usage unique, expiré après vérification

// ❌ Stocker les clés publiques en clair sans vérification du counter
// → Le counter monte à chaque authentification — s'il descend, c'est un replay attack

// ❌ rpID ne correspond pas au domaine
// Ce sont les browsers qui vérifient l'origin binding — une passkey enregistrée
// sur tribuzen.fr ne fonctionnera JAMAIS sur tribuzen-phishing.fr

// ✅ Toujours vérifier expectedOrigin et expectedRPID côté serveur
```

---

## Checklist

- [ ] Je comprends pourquoi les passkeys éliminent le phishing (origin binding)
- [ ] Je connais les deux cérémonies : registration et authentication
- [ ] J'ai implémenté `generateRegistrationOptions` et `verifyRegistrationResponse`
- [ ] J'ai implémenté `generateAuthenticationOptions` et `verifyAuthenticationResponse`
- [ ] Le counter est mis à jour après chaque authentification (protection replay)
- [ ] Je comprends `backedUp: true` = synchronisation Keychain = récupération automatique
- [ ] La stratégie de récupération sans Keychain est documentée et communicée à l'utilisateur
