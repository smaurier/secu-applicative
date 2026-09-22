# Lab 04 — Intervention : relire une PR d'authentification, findings avant vérité

> **Outcome :** à la fin, tu sais repérer, dans un module de session "maison" qui marche et
> dont la démo passe, deux failles discrètes : une session qui n'expire jamais (peu importe
> la date qu'on lui a donnée), et une comparaison de signature qui ne protège pas contre les
> attaques temporelles.
> **Vrai outil :** `node:crypto` (`timingSafeEqual`). Deux preuves différentes, honnêtement
> distinguées : l'expiration se prouve par le COMPORTEMENT (un vrai token expiré, une vraie
> horloge) ; la comparaison à temps constant se prouve par une RELECTURE DU SOURCE (son
> intérêt est justement de résister à une mesure de timing, ce qu'un test rapide en CI ne
> peut pas fiablement démontrer lui-même).
> **Feedback :** `npm run lab:04` — non-régression déjà verte, revue rouge sur les deux
> failles. `npm run solution:04` prouve l'oracle. `REVIEW.md` se remplit AVANT tout code.

## Prérequis technique

`npm install` depuis `14-securite-applicative/labs`.

## Lire avant (une lecture bornée)

- Module [`03-authentification.md`](../../modules/03-authentification.md) — cycle de vie
  d'une session, pourquoi une expiration est non négociable.
- Module [`05-cryptographie.md`](../../modules/05-cryptographie.md) — comparaison à temps
  constant, `timingSafeEqual`.

## Énoncé

`src/SessionToken.ts` est **en production**. Un collègue a ouvert la PR, elle est déjà
mergée : la démo passe (signer puis vérifier un token frais fonctionne, un token altéré est
rejeté).

**0. `REVIEW.md`, avant toute ligne de code.** Lis UNIQUEMENT `src/SessionToken.ts` et
réponds aux questions.

**1. Corrige les deux failles**, signatures publiques inchangées :
- `verifySession` doit rejeter un token dont `expiresAt` est dans le passé.
- La comparaison de signature doit passer par `timingSafeEqual` (pas `!==`/`===` sur des
  chaînes).

**Le piège à éviter.** `timingSafeEqual` exige deux `Buffer` de MÊME LONGUEUR (il lève une
exception sinon) — vérifie la longueur AVANT de l'appeler, sans quoi une signature d'une
longueur différente fait planter la fonction au lieu de simplement rejeter le token.

## Étapes (en friction)

1. Remplis `REVIEW.md`.
2. `npm run lab:04` : non-régression verte, revue rouge.
3. Ajoute la vérification d'expiration dans `verifySession`.
4. Remplace la comparaison de signature par `timingSafeEqual` (avec la vérification de
   longueur au préalable).
5. Relance : les 6 tests doivent passer.

## Vérifier

```bash
cd 14-securite-applicative/labs
npm install
npm run lab:04
npm run solution:04
```

**Ce que l'oracle vérifie**

Non-régression : token frais valide, token altéré rejeté, token malformé rejeté. Revue : un
token dont `expiresAt` est dans le passé est rejeté même avec une signature valide, un token
encore valide dans le temps reste accepté ; le code source utilise bien `timingSafeEqual`
et plus une comparaison de chaînes directe.

## Variante J+30 (fading)

`SECRET` est une chaîne codée en dur dans le fichier. Où devrait-elle vivre en production,
et quel est le risque concret si ce fichier est un jour rendu public (dépôt open source,
fuite) ?

## Application TribuZen

Même revue sur le module de session réel de `tribuzen-api` (cours 09, AuthModule) — en
pratique, une bibliothèque (`jsonwebtoken`, `jose`) gère déjà ces deux points correctement,
mais il faut savoir POURQUOI pour auditer un code qui, lui, les a réimplémentés à la main.
Commit : `fix(session): expiration vérifiée + comparaison de signature à temps constant`.
