# Lab 03 — Intervention : poser une CSP stricte sur un front existant, sans rien casser

> **Outcome :** à la fin, tu sais écrire une Content-Security-Policy stricte pour une vraie
> app (pas un exemple jouet) qui a un besoin réel de charger une lib tierce ET un script
> inline de bootstrap — et tu sais que "strict" ne veut PAS dire "tout casser" : chaque
> ressource légitime existante doit continuer à charger.
> **Vrai outil :** un parseur de CSP écrit pour ce lab, qui lit ton en-tête exactement comme
> un navigateur le ferait (directive par directive, source par source).
> **Feedback :** `npm run lab:03` — RED tant que `buildCsp` ne satisfait pas l'inventaire ET
> la rigueur attendue. `npm run solution:03` prouve l'oracle.

## Prérequis technique

`npm install` depuis `14-securite-applicative/labs`.

## Lire avant (une lecture bornée)

- Module [`06-headers-securite.md`](../../modules/06-headers-securite.md) — CSP, nonce vs
  hash vs `unsafe-inline` : pourquoi `unsafe-inline` annule presque tout l'intérêt d'une CSP
  contre le XSS (un script injecté est... inline, par définition).

## Énoncé

Le front TribuZen existant charge : une lib tierce depuis un CDN, un script inline de
bootstrap (pose une variable globale avant le bundle), des images depuis un host dédié, et
fait des appels réseau vers l'API. Lis l'inventaire complet en tête de `src/buildCsp.ts`.

Écris `buildCsp(nonce)` : une CSP qui autorise EXACTEMENT cet inventaire, rien de plus,
jamais via `unsafe-inline`/`unsafe-eval`.

**Le piège à éviter.** Le réflexe le plus courant face à "j'ai un script inline à
autoriser" est d'ajouter `'unsafe-inline'` à `script-src` — ça "marche" instantanément, mais
ça autorise AUSSI n'importe quel script injecté par un XSS, exactement ce que la CSP est
censée bloquer. La bonne réponse est un `nonce` : une valeur aléatoire générée à CHAQUE
réponse HTTP, posée à la fois dans l'en-tête CSP et sur l'attribut `nonce` du `<script>`
légitime — un script injecté par un attaquant ne connaît jamais le nonce du jour.

## Étapes (en friction)

1. `npm run lab:03` : RED — `buildCsp` n'existe pas encore.
2. Écris les directives une par une, en vérifiant CHAQUE ressource de l'inventaire au fur et
   à mesure (`script-src`, `style-src`, `img-src`, `connect-src`).
3. Ajoute le nonce paramétré pour le script inline — jamais une valeur fixe.
4. Ajoute `object-src 'none'` et `base-uri 'self'` (durcissement indépendant de
   l'inventaire, toujours recommandé).
5. Relance : les 7 tests doivent passer.

## Vérifier

```bash
cd 14-securite-applicative/labs
npm install
npm run lab:03
npm run solution:03
```

**Ce que l'oracle vérifie**

Rien de l'inventaire existant n'est cassé (CDN, images, API tous autorisés) ; le script
inline passe par un nonce paramétré (deux appels à `buildCsp` avec des nonces différents
produisent des en-têtes différents — preuve que ce n'est pas une valeur figée) ; aucune
directive ne contient `unsafe-inline` ni `unsafe-eval` ; `object-src 'none'` et
`base-uri 'self'` sont présents.

## Variante J+30 (fading)

Le produit ajoute Google Analytics (script tiers + appels `connect-src` vers
`google-analytics.com`). Comment l'intégrer sans élargir `script-src` à `*` ni affaiblir le
reste de la politique ?

## Application TribuZen

Même CSP posée en vrai sur `tribuzen-admin` (Next.js, middleware qui génère un nonce par
requête) — d'abord en mode `Content-Security-Policy-Report-Only` pour observer les
violations avant de bloquer (cours module 06 §migration progressive). Commit :
`feat(security): CSP stricte, nonce par requête, aucune régression sur les ressources existantes`.
