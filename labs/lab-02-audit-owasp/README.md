# Lab 02 — Intervention : auditer une appli, corriger le top 3 (OWASP)

> **Outcome :** à la fin, tu as audité un module d'authentification qui MARCHE (la démo
> passe) et trouvé trois failles réelles, classées OWASP Top 10 2021 — puis corrigées, avec
> une preuve mesurée pour chacune (jamais "je pense que c'est mieux").
> **Vrai outil :** `node:crypto` (`scryptSync`, `timingSafeEqual`, `randomBytes`) — un vrai
> hachage lent et salé, pas une bibliothèque tierce à configurer.
> **Feedback :** `npm run lab:02` — RED sur les trois failles. `npm run solution:02` prouve
> l'oracle. `AUDIT.md` se remplit AVANT tout code, le correcteur le lit en premier.

## Prérequis technique

`npm install` depuis `14-securite-applicative/labs`.

## Lire avant (une lecture bornée)

- Module [`01-owasp-top10.md`](../../modules/01-owasp-top10.md) — les 10 catégories, comment
  classer une faille donnée.
- Module [`05-cryptographie.md`](../../modules/05-cryptographie.md) — pourquoi un hash
  "rapide" (SHA-256 seul) est un mauvais choix pour un mot de passe, et ce que le sel change
  concrètement.

## Énoncé

`UserAccountService` (`src/UserAccountService.ts`) est **en production**. Ticket : *« avant
d'ouvrir l'inscription au public, un audit de sécurité rapide sur ce module. »*

**0. `AUDIT.md`, avant toute ligne de code.** Lis UNIQUEMENT `src/UserAccountService.ts` et
réponds aux questions.

**1. Corrige les trois failles**, en gardant les signatures publiques (`register`, `login`)
inchangées :
- **A02 Cryptographic Failures** : hash salé (un sel aléatoire PAR utilisateur), avec une
  fonction de dérivation lente (`scryptSync`, pas un simple SHA-256).
- **A04 Insecure Design** : une politique de mot de passe minimale (longueur, pas un
  classique du top des mots de passe les plus utilisés).
- **A07 Identification and Authentication Failures** : verrouillage du compte après
  plusieurs échecs de connexion consécutifs.

**Le piège à éviter.** Comparer les hash avec `===` reste un problème même une fois salé :
la comparaison de chaînes s'arrête au premier caractère différent, ce qui fuit un
micro-timing exploitable en théorie. Utilise `timingSafeEqual` (déjà dans `node:crypto`)
pour la comparaison finale.

## Étapes (en friction)

1. Remplis `AUDIT.md`.
2. `npm run lab:02` : RED sur les trois failles, les cas nominaux (inscription/connexion
   normales) passent déjà.
3. Corrige A02, relance, corrige A04, relance, corrige A07, relance.
4. GREEN sur les 7 tests.

## Vérifier

```bash
cd 14-securite-applicative/labs
npm install
npm run lab:02
npm run solution:02
```

**Ce que l'oracle vérifie**

A02 : deux comptes avec le MÊME mot de passe ont des hash stockés DIFFÉRENTS (preuve du
sel) ; la connexion continue de fonctionner malgré le sel. A04 : un mot de passe trop court
ou trop commun est refusé à l'inscription ; un mot de passe raisonnable est accepté. A07 :
après 5 échecs, même le BON mot de passe échoue ensuite (compte verrouillé) ; un utilisateur
avec peu d'échecs reste connectable normalement.

## Variante J+30 (fading)

Le verrouillage actuel est PERMANENT (jamais de déverrouillage). Quel est le risque business
de cette version ? Propose une politique de déverrouillage (délai, ou action admin) et le
test qui la prouverait.

## Application TribuZen

Même audit sur le module d'auth réel de `tribuzen-api` (cours 09, lab 02 AuthModule), avec
en plus `bcrypt`/`argon2` (bibliothèques dédiées) plutôt que `scrypt` maison. Commit :
`fix(auth): hash salé + politique de mot de passe + verrouillage après échecs répétés`.
