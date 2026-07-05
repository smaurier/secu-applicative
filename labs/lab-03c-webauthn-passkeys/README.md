<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Lab 03c — Concevoir un flux WebAuthn / passkeys pour TribuZen (défensif)

> **Outcome :** à la fin, tu sais **concevoir et spécifier** un flux d'authentification par passkey (registration + authentication) pour un produit à données sensibles, avec les vérifications serveur, le stockage des credentials et une stratégie de fallback — sans réimplémenter la crypto.
> **Vrai outil :** un vrai backend (NestJS/Express) + le Web Authentication API natif du navigateur + une bibliothèque WebAuthn serveur maintenue (tu la choisis et la câbles toi-même). **JAMAIS de harnais simulé.**
> **Feedback :** le coach valide ta conception et ta démo en session — pas de test-runner auto-correcteur.
> **Cadre défensif :** on **durcit** l'authentification de TON app (TribuZen). Aucune attaque contre un système tiers.

---

## Énoncé

TribuZen veut supprimer les mots de passe pour le login parent, à cause du risque de phishing sur des données de famille sensibles. Ta mission : **concevoir le flux passkey de bout en bout et le rendre défendable**, puis en démontrer le chemin heureux dans un navigateur.

Tu produis **deux livrables** :

1. **Une note de conception** (`DESIGN.md`, ~1 page) qui répond aux décisions ci-dessous.
2. **Un prototype minimal fonctionnel** : les 4 routes serveur + les 2 appels client, qui permet d'enregistrer une passkey puis de se connecter avec, en local (`https://localhost` ou `http://localhost` — localhost est traité comme origine sécurisée par les navigateurs).

Contexte fixé (à respecter) :

- RP : TribuZen, domaine de prod `tribuzen.fr`, origine `https://tribuzen.fr` (en dev : `localhost`).
- Données protégées : santé enfants, agendas, adresses → **user verification obligatoire**.
- Cible : parents grand public sur iOS/Android/desktop récents.

**Pas de gap-fill, pas de squelette pré-rempli à trous.** Tu pars du starter minimal ci-dessous et tu écris le reste.

### Décisions à trancher dans `DESIGN.md`

1. **Synchronisée ou device-bound** pour le login parent ? Justifie via le critère récupération vs non-copie. Que fais-tu de différent pour un compte **admin/facturation** ?
2. **`residentKey`** : quelle valeur, et quelle conséquence UX (login avec ou sans identifiant) ?
3. **Challenge** : où le stockes-tu, quel TTL, et comment garantis-tu l'usage unique ?
4. **Liste exacte des vérifications serveur** à la registration ET à l'authentication (au moins 6, cf. module §2.8).
5. **Fallback de récupération** : que se passe-t-il si un parent perd son seul appareil ? Décris ta règle « au moins deux moyens ».
6. **Ce que tu NE stockes jamais** côté serveur, et pourquoi une fuite de ta base ne compromet pas les comptes.

### Starter minimal

Crée un petit backend et un client. Rien n'est fourni « clé en main » — voici seulement les points d'ancrage :

```ts
// server — 4 routes à écrire toi-même
// POST /api/auth/passkey/register/start   -> renvoie PublicKeyCredentialCreationOptions (challenge inclus)
// POST /api/auth/passkey/register/finish  -> vérifie l'attestation, stocke la clé publique
// POST /api/auth/passkey/login/start      -> renvoie PublicKeyCredentialRequestOptions (nouveau challenge)
// POST /api/auth/passkey/login/finish     -> vérifie l'assertion (signature), ouvre la session

// Tu choisis et installes une lib WebAuthn serveur maintenue (ne réimplémente PAS la crypto).
// Tu lui passes TOUJOURS expectedOrigin / expectedRPID / expectedChallenge explicites.
```

```html
<!-- client — page minimale -->
<button id="register">Créer une passkey</button>
<button id="login">Se connecter avec une passkey</button>
<!-- pour l'autofill usernameless (bonus) : -->
<input autocomplete="username webauthn" />
<script type="module" src="/passkey-client.js"></script>
```

```ts
// passkey-client.js — à écrire : appelle navigator.credentials.create() puis .get()
// pense à décoder challenge/user.id (base64url -> ArrayBuffer) et à sérialiser via credential.toJSON()
```

Modèle de stockage minimal (à définir toi-même, ex. table `Passkey`) : `credentialId` (unique, index), `publicKey`, `counter`, `userId`, `backedUp`, `deviceType`, `createdAt`.

---

## Étapes (en friction)

1. **Rédige `DESIGN.md`** en répondant aux 6 décisions AVANT de coder. C'est le cœur défensif du lab.
2. **Route `register/start`** : génère des options avec `rpID` = domaine, `residentKey`/`userVerification` selon ta décision, `excludeCredentials` des passkeys déjà liées. Stocke le challenge (usage unique, TTL court).
3. **Client `create()`** : décode le challenge, appelle `navigator.credentials.create({publicKey})`, gère `InvalidStateError` (déjà enregistrée) et `NotAllowedError` (annulation).
4. **Route `register/finish`** : vérifie l'attestation avec `expectedOrigin`/`expectedRPID`/`expectedChallenge` **explicites**, supprime le challenge, stocke clé publique + `credentialId` + `counter` + `backedUp`.
5. **Route `login/start`** : **nouveau** challenge ; `allowCredentials` vide (passkey discoverable) ou ciblé selon ton choix.
6. **Client `get()`** : appelle `navigator.credentials.get({publicKey})`, renvoie l'assertion via `toJSON()`.
7. **Route `login/finish`** : retrouve la passkey par `credentialId`, vérifie la signature contre la clé publique, **fais avancer le counter**, ouvre la session.
8. **Démo chemin heureux** : enregistre une passkey (Face ID / Windows Hello / PIN) puis reconnecte-toi. Montre-le au coach.
9. **Test défensif manuel** : change temporairement `expectedOrigin` en une valeur fausse → la vérification DOIT échouer. Note ce que ça prouve.

---

## Corrigé complet commenté

> Ce lab est un exercice de **conception + câblage** : il n'y a pas UNE seule solution de code. Voici les **décisions attendues** et la **structure de référence**. Le coach valide la cohérence, pas une correspondance ligne à ligne.

### `DESIGN.md` — réponses de référence

1. **Login parent = passkey synchronisée.** Critère décisif : la **récupération**. Un parent change de téléphone régulièrement ; la synchro (iCloud/Google) fait réapparaître la passkey sans lockout. Le compromis (stockage dépendant du compte cloud) est acceptable pour ce niveau de risque. **Admin/facturation** : proposer **en plus** une passkey **device-bound** (clé matérielle, `authenticatorAttachment: "cross-platform"`) — privilèges élevés → exigence de non-copie (lien module 04, moindre privilège).
2. **`residentKey: "required"`** → passkey **discoverable** → login **sans identifiant** (le navigateur propose les passkeys du domaine). UX cible pour du grand public. Bonus : `mediation: "conditional"` pour l'autofill.
3. **Challenge** stocké côté serveur (cache/DB) indexé par utilisateur ou par tentative, **TTL 2–5 min**, lu via un `take()` atomique (lecture **+** suppression) → usage unique garanti.
4. **Vérifications serveur** (les deux cérémonies) :
   - challenge == émis, non expiré, à usage unique (puis supprimé) ;
   - `expectedOrigin == https://tribuzen.fr` (dev : `http://localhost:PORT`) ;
   - `rpIdHash == hash(tribuzen.fr)` ;
   - flag **user verification** présent (car `required`) ;
   - (auth) **signature** valide contre la clé publique stockée pour ce `credentialId` ;
   - (auth) **counter** strictement croissant si non nul.
5. **Fallback** : règle « **au moins deux moyens** » par compte — 2 passkeys enregistrées, OU 1 passkey synchronisée, OU 1 passkey + email vérifié avec code à usage unique pour ré-enrôler une nouvelle passkey. Perte du seul appareil sans backup → parcours de récupération par email + facteur secondaire (jamais un simple « mot de passe oublié »).
6. **Jamais stocké** : clé privée, secret partagé, mot de passe. On stocke seulement des **clés publiques**, `credentialId`, `counter`, métadonnées. Une fuite de base ne donne que du matériel public → **inexploitable** pour se faire passer pour un utilisateur (impossible de forger une signature).

### Structure serveur de référence (lib-agnostique)

```ts
// passkey.service.ts — la crypto est déléguée à la lib WebAuthn choisie.
// La valeur défensive du lab = ces invariants, PAS la réécriture de la crypto.

const RP_ID = process.env.RP_ID ?? 'localhost'
const ORIGIN = process.env.RP_ORIGIN ?? 'http://localhost:5173'

async function registerFinish(userId: string, body: unknown) {
  const expectedChallenge = challengeStore.take(userId) // lit ET supprime
  if (!expectedChallenge) throw new Unauthorized('Challenge expiré/absent.')

  const result = await webauthn.verifyRegistrationResponse({
    response: body,
    expectedChallenge,
    expectedOrigin: ORIGIN,     // verrou anti-phishing — explicite, jamais dérivé du Host
    expectedRPID: RP_ID,
    requireUserVerification: true,
  })
  if (!result.verified) throw new Unauthorized('Attestation invalide.')

  const info = result.registrationInfo
  await passkeyRepo.save({
    userId,
    credentialId: info.credentialID,      // clé de recherche à l'auth
    publicKey: info.credentialPublicKey,  // publique => stockable
    counter: info.counter,
    backedUp: info.credentialBackedUp,    // true => passkey synchronisée (BE/BS)
    deviceType: info.credentialDeviceType,
  })
}

async function loginFinish(body: { id: string }) {
  const passkey = await passkeyRepo.findByCredentialId(body.id)
  if (!passkey) throw new Unauthorized('Credential inconnue.')

  const expectedChallenge = challengeStore.take(passkey.userId)
  const result = await webauthn.verifyAuthenticationResponse({
    response: body,
    expectedChallenge,
    expectedOrigin: ORIGIN,
    expectedRPID: RP_ID,
    requireUserVerification: true,
    credential: {
      id: passkey.credentialId,
      publicKey: passkey.publicKey,
      counter: passkey.counter,
    },
  })
  if (!result.verified) throw new Unauthorized('Signature invalide.')

  // anti-replay : le counter doit progresser
  await passkeyRepo.updateCounter(passkey.id, result.authenticationInfo.newCounter)
  return session.issueFor(passkey.userId) // session à durcir (module 06)
}
```

**Pourquoi ce corrigé est défendable :**
- `expectedOrigin`/`expectedRPID` sont des **constantes de config**, jamais dérivées de la requête entrante → le verrou anti-phishing tient même si un attaquant contrôle des en-têtes.
- Le challenge est **pris-et-supprimé** → usage unique réel, pas de rejeu.
- `requireUserVerification: true` → la passkey est un facteur **fort** (possession appareil + biométrie/PIN).
- Le **counter avance** → une credential clonée qui rejoue une vieille assertion est détectable.
- Seules des **données publiques** touchent la base → surface de compromission minimale.

### Grille d'évaluation (le coach coche)

| Critère | Attendu | OK ? |
|---|---|---|
| `DESIGN.md` tranche synchro vs device-bound **avec justification** | récupération vs non-copie explicités | |
| `residentKey` choisi et conséquence UX expliquée | `required` + login usernameless | |
| Challenge : usage unique + TTL décrits ET implémentés | `take()` atomique, TTL court | |
| ≥ 6 vérifications serveur listées ET présentes dans le code | cf. §2.8 module | |
| `expectedOrigin`/`expectedRPID` en config, jamais dérivés de la requête | constantes | |
| Counter mis à jour à chaque login | anti-replay | |
| Fallback « au moins deux moyens » spécifié | pas de lockout définitif | |
| Aucune clé privée / secret partagé stockée | base = données publiques only | |
| Démo : registration puis login fonctionnent dans un navigateur réel | chemin heureux vu en session | |
| Test défensif : mauvais `expectedOrigin` → échec vérifié | l'apprenant l'a provoqué et compris | |

### Coaching — questions à poser en session

- « Un attaquant a une copie complète de ta base. Peut-il se connecter à un compte ? Pourquoi non ? »
- « Le parent clique sur le lien de phishing `tribuzen-support.fr` et arrive sur une copie parfaite. Que se passe-t-il quand il essaie sa passkey ? Où, précisément, ça bloque ? »
- « Tu dérives `expectedRPID` du header `Host` de la requête pour ‘simplifier’. Quel verrou viens-tu de casser ? »
- « Le parent perd son iPhone, en rachète un. Que se passe-t-il selon ton choix synced/device-bound ? Et s'il n'avait qu'une clé matérielle device-bound ? »
- **Signal rouge** : si l'apprenant réimplémente la vérification de signature à la main → recadrer vers une lib maintenue (surface d'erreur crypto énorme).

---

## Variante J+30 (fading)

**Même objectif, contraintes ajoutées, sans rouvrir ce corrigé ni le module :**

1. **En 45 min**, re-spécifie et re-câble le flux **de mémoire**.
2. Ajoute **la gestion multi-passkeys** : un compte peut enregistrer plusieurs passkeys (téléphone + clé matérielle) et en **révoquer** une (route `DELETE /api/auth/passkey/:id`), sans jamais tomber sous « deux moyens » restants.
3. Ajoute l'**autofill usernameless** : `mediation: "conditional"` + `<input autocomplete="username webauthn">`, gardé derrière `PublicKeyCredential.isConditionalMediationAvailable()`.
4. **Contrainte défensive** : rédige en 5 lignes ce que tu **loggues** (et ce que tu ne loggues **jamais**) lors d'un échec de vérification, pour l'audit (lien module 11).

**Critère de réussite :** registration + login fonctionnent, une passkey peut être révoquée sans créer de lockout, et tu peux expliquer à voix haute pourquoi le phishing du §1 échoue.

---

## Application TribuZen

Dans le repo `smaurier/tribuzen`, le flux vit ici :

```
tribuzen/
  apps/api/src/auth/
    passkey.controller.ts    ← 4 routes register/login start|finish
    passkey.service.ts       ← generate/verify (lib WebAuthn), invariants défensifs
    challenge.store.ts       ← challenges usage unique, TTL court
  apps/web/src/features/auth/
    passkey-client.ts        ← navigator.credentials.create / get
    LoginPasskeyButton.vue   ← bouton + conditional mediation
```

**Différences par rapport au lab :**

- Le `challenge.store` utilisera le cache de prod (Redis) avec TTL natif, pas une Map en mémoire.
- Le modèle `Passkey` sera une vraie table Prisma reliée à `User` (`onDelete: Cascade`), avec `lastUsedAt` pour l'audit.
- La politique admin (passkey device-bound obligatoire pour les rôles à privilèges) sera reliée au module 04 (autorisation).
- La session émise après login sera durcie selon le module 06 (cookie `HttpOnly` + `Secure` + `SameSite`, rotation).

**Commit cible :**
```
feat(auth): login par passkey (WebAuthn) — registration + auth, vérif origin/challenge/counter, fallback
```
