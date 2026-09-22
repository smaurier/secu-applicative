# Lab 01 — PKCE de zéro : le flux qui protège OAuth2 pour un client public

> **Outcome :** à la fin, tu as implémenté PKCE (RFC 7636) — le mécanisme qui protège le
> flux OAuth2 Authorization Code quand le client ne peut garder aucun secret (SPA, app
> mobile). Tu sais pourquoi un `code` intercepté seul ne suffit JAMAIS à obtenir un token,
> et tu l'as prouvé en simulant l'attaque, pas en la décrivant.
> **Vrai outil :** `node:crypto` (SHA-256, aléatoire cryptographique réel). La dérivation
> est vérifiée contre le **vecteur de test officiel de la RFC 7636 Annexe B** — pas "à peu
> près la bonne formule", exactement celle du standard.
> **Feedback :** `npm run lab:01` — RED tant que `src/` ne satisfait pas l'oracle.
> `npm run solution:01` prouve l'oracle.

## Périmètre de ce lab (honnêteté)

Ce lab couvre **PKCE en entier**, le cœur mécanique et 100% testable du flux. L'OIDC complet
(discovery, validation d'ID token, claims) et WebAuthn (authenticateurs matériels/
plateforme) ont besoin d'un vrai fournisseur d'identité ou d'un navigateur avec matériel
crypto — hors du périmètre d'un oracle vitest+node. Lis les modules 03b et 03c pour la
théorie ; ce lab te fait construire et prouver la partie qui, elle, se prouve entièrement en
code.

## Prérequis technique

`npm install` depuis `14-securite-applicative/labs`.

## Lire avant (une lecture bornée)

- Module [`03b-oidc-pkce-client.md`](../../modules/03b-oidc-pkce-client.md) — le flux
  complet, où PKCE s'insère, pourquoi "plain" (sans hash) n'apporte aucune protection.

## Énoncé

Construis, de zéro :

- `src/pkce.ts` — `generateCodeVerifier()` (aléatoire, conforme RFC) et
  `deriveCodeChallenge(verifier)` (SHA-256 + base64url, méthode S256).
- `src/AuthorizationServer.ts` — le serveur d'autorisation minimal : émet un `code` associé
  à un `challenge`, l'échange contre un token SEULEMENT si le `verifier` présenté
  correspond, et RESTE un code à usage unique même en cas de succès.

Lis les commentaires en tête de chaque fichier pour le contrat exact.

**Le piège à éviter.** Une implémentation qui vérifie le `verifier` mais CONSOMME le `code`
même en cas d'échec (mismatch) ouvre une fenêtre d'attaque : un tiers qui intercepte le
`code` et essaie un mauvais verifier "grille" le code pour le VRAI client légitime derrière
lui. Le code ne doit être consommé QUE sur un échange réussi.

## Étapes (en friction)

1. `npm run lab:01` : RED partout.
2. Implémente `generateCodeVerifier` et `deriveCodeChallenge` — vérifie IMMÉDIATEMENT contre
   le vecteur RFC (le test est déjà là) avant de toucher au serveur.
3. Implémente `AuthorizationServer` : stockage code → challenge, vérification à l'échange,
   consommation à usage unique.
4. Relance : les 8 tests doivent passer, dont les deux tests de SÉCURITÉ.

## Vérifier

```bash
cd 14-securite-applicative/labs
npm install
npm run lab:01
npm run solution:01
```

**Ce que l'oracle vérifie**

`generateCodeVerifier` : longueur RFC-conforme, alphabet autorisé, vraiment aléatoire.
`deriveCodeChallenge` : reproduit EXACTEMENT le vecteur de test officiel de la RFC 7636
Annexe B. `AuthorizationServer` : flux nominal complet ; un `code` volé est inutilisable
sans le bon `verifier` (`PkceMismatchError`) ; un `code` est à usage unique, même avec le
bon `verifier` au second essai (`InvalidGrantError`) ; un `code` jamais émis est rejeté.

## Variante J+30 (fading)

Le serveur ne purge jamais les `code` non consommés après un délai. Quel est le risque
concret ? Ajoute une expiration (ex. 60 secondes) et le test qui la prouve.

## Application TribuZen

Même PKCE sur le flux de connexion de `tribuzen-admin` (Next.js) face à
`tribuzen-api`/AuthModule (cours 09, lab 02). Commit :
`feat(auth): PKCE RFC 7636, vérifié contre le vecteur de test officiel`.
