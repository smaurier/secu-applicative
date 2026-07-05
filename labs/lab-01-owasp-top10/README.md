<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Lab 01 — Cartographie & priorisation OWASP de TribuZen

> **Outcome :** à la fin, tu sais produire une **carte des risques OWASP** d'une application réelle (constat → catégorie A0x → parade défensive) et la **prioriser** par Risque = Probabilité × Impact pour décider par quoi commencer.
> **Vrai outil :** un document Markdown versionné (`owasp-risk-map.md`) — c'est le livrable exact d'une revue de sécurité en poste. Support de référence : la page officielle [owasp.org/Top10/2021](https://owasp.org/Top10/2021/) et les [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/).
> **Feedback :** le coach valide la carte en session (classification + priorisation + justification). Pas de test-runner auto-correcteur : une revue de sécurité se **défend à l'oral**, pas au vert/rouge.
>
> **⚠️ Défensif.** On **cartographie et on durcit**, on n'attaque pas. Aucune exploitation d'un système tiers : le seul « système » ici est TribuZen, décrit sur papier.

---

## Énoncé

La CTO de TribuZen (app famille : agendas, listes, **données d'enfants**) te demande une revue de sécurité **avant** toute nouvelle feature. Tu as relevé **12 constats** dans le code et l'infra. Ton livrable : un fichier `owasp-risk-map.md` qui, pour chaque constat, donne **la catégorie OWASP**, **la parade défensive** et **une priorité justifiée**, puis conclut par un **plan « par quoi on commence »**.

**Les 12 constats de la revue :**

1. `GET /api/families/:id/children` ne vérifie pas que la famille appartient à l'utilisateur connecté (un `familyId` deviné expose les enfants d'une autre famille).
2. Les mots de passe sont hachés en **MD5**.
3. La recherche construit la requête SQL par **concaténation** : `... WHERE name LIKE '%' + req.query.q + '%'`.
4. Le reset de mot de passe repose sur une **question secrète** (« nom de ton premier animal »).
5. Aucun header de sécurité ; le serveur renvoie `cors({ origin: '*' })` et la **stack trace** en prod.
6. `npm audit` remonte **1 vulnérabilité critique** dans une dépendance transitive.
7. `/api/login` n'a **aucun rate limiting**.
8. Les webhooks entrants (paiement) sont traités **sans vérifier de signature**.
9. **Aucun log** des échecs d'authentification ni des accès refusés.
10. L'endpoint « aperçu de lien » exécute `axios.get(url)` sur une **URL fournie par l'utilisateur**.
11. Le front affiche des notes de famille via `v-html` **sans sanitization**.
12. Le token JWT est stocké et vérifié, mais **`alg: none`** est accepté par le vérificateur.

> **Pas de gap-fill.** Tu produis le document complet à partir de la trame ci-dessous.

### Trame de départ (`owasp-risk-map.md`)

```markdown
# TribuZen — Carte des risques OWASP 2021

| # | Constat | Catégorie OWASP | Parade défensive | Proba | Impact | Priorité |
|---|---------|-----------------|------------------|-------|--------|----------|
| 1 | Accès enfants sans contrôle de propriété | ... | ... | ... | ... | ... |
| ...

## Plan de remédiation (par quoi on commence)
1. ...
```

---

## Étapes (en friction)

1. **Classe les 12 constats.** Pour chacun, écris la catégorie officielle exacte (`A01 Broken Access Control`, … `A10 SSRF`). Attention aux pièges : #1 est authentifié mais mal **autorisé** ; #2 touche crypto **et** auth (choisis la dominante).
2. **Écris la parade défensive** de chaque ligne en une phrase actionnable (le « quoi faire », pas « c'est dangereux »).
3. **Note Proba et Impact** (Faible / Moyenne / Haute) pour chacun. **Majore l'impact** dès qu'un constat touche les données d'enfants ou de comptes.
4. **Déduis la priorité** 🔴 Critique / 🟠 Haute / 🟡 Moyenne / 🔵 Base à partir de Risque = Proba × Impact — **jamais** à partir du numéro de catégorie.
5. **Rédige le plan** « par quoi on commence » : 3 à 4 actions en tête, en distinguant les **quick wins** (effort faible, gain fort) des **chantiers** (refonte de design).
6. **Vérifie la couverture :** les 12 constats couvrent-ils bien les 10 catégories A01–A10 ? (Deux constats tombent dans la même catégorie — lesquels ?)

---

## Corrigé complet commenté

> Classification + priorisation de référence. Les niveaux de priorité sont défendables autrement ; ce qui compte, c'est la **cohérence** avec Risque = Proba × Impact et l'impact **majoré** pour les données sensibles.

```markdown
# TribuZen — Carte des risques OWASP 2021

| #  | Constat                                   | Catégorie OWASP                        | Parade défensive                                                   | Proba   | Impact    | Priorité      |
|----|-------------------------------------------|----------------------------------------|--------------------------------------------------------------------|---------|-----------|---------------|
| 1  | Accès enfants sans contrôle de propriété  | A01 Broken Access Control              | Vérifier côté serveur `family.ownerId === req.user.id`, deny by default | Haute   | Critique  | 🔴 Critique   |
| 3  | SQL par concaténation de `req.query.q`    | A03 Injection                          | Requête paramétrée (`LIKE $1`), jamais de concaténation            | Haute   | Critique  | 🔴 Critique   |
| 11 | `v-html` sans sanitization                | A03 Injection (XSS)                    | Éviter `v-html` ; si nécessaire, sanitizer (DOMPurify) + CSP        | Haute   | Haute     | 🔴 Critique   |
| 12 | JWT accepte `alg: none`                   | A07 Auth Failures                      | Imposer l'algo attendu à la vérification, rejeter `none`           | Haute   | Critique  | 🔴 Critique   |
| 2  | Mots de passe en MD5                      | A02 Cryptographic Failures            | Re-hacher en bcrypt/argon2 ; jamais MD5/SHA1 pour un mot de passe  | Moyenne | Critique  | 🟠 Haute      |
| 7  | Pas de rate limiting sur `/login`         | A07 Auth Failures                      | Rate limiter + verrou temporaire de compte, MFA                    | Haute   | Haute     | 🟠 Haute      |
| 5  | Headers absents, CORS `*`, stack en prod  | A05 Security Misconfiguration          | `helmet()`, CORS restreint à l'origine du front, masquer les erreurs | Haute   | Moyenne   | 🟡 Moyenne    |
| 6  | Dépendance critique (`npm audit`)         | A06 Vulnerable and Outdated Components | `npm audit fix` / `overrides`, veille CVE (Dependabot)             | Moyenne | Variable  | 🟡 Moyenne    |
| 10 | « Aperçu de lien » sur URL utilisateur    | A10 SSRF                               | Allow-list de domaines, bloquer IP privées et `169.254.169.254`    | Moyenne | Haute     | 🟡 Moyenne    |
| 8  | Webhooks sans vérification de signature   | A08 Software/Data Integrity Failures  | Vérifier une signature HMAC en timing-safe avant de traiter        | Moyenne | Haute     | 🟡 Moyenne    |
| 4  | Reset via question secrète                | A04 Insecure Design                    | Refondre : token à usage unique, expirant, envoyé par email        | Moyenne | Haute     | 🔵 Base (chantier) |
| 9  | Aucun log d'échec d'auth / accès refusé   | A09 Logging & Monitoring Failures      | Logger login/échecs/accès refusés en JSON, centraliser, alerter    | —       | Transverse| 🔵 Base (socle, à faire tôt) |

## Plan de remédiation (par quoi on commence)

**Bloc 1 — Fermer les portes ouvertes exposées + critiques (aujourd'hui) :**
1. **#1 (A01)** — contrôle de propriété sur l'accès aux enfants. Données de mineurs exposées = priorité absolue.
2. **#3 (A03)** — requête paramétrée sur la recherche. Injection = compromission possible de toute la base.
3. **#12 (A07)** — rejeter `alg: none` à la vérification JWT. Contournement d'auth trivial.
4. **#11 (A03/XSS)** — retirer le `v-html` non sanitizé sur les notes de famille.

**Bloc 2 — Quick wins à effort quasi nul (dans la foulée) :**
5. **#7 (A07)** — un middleware de rate limiting sur `/login`.
6. **#5 (A05)** — `helmet()` + CORS restreint + masquage des stack traces.
7. **#2 (A02)** — plan de re-hachage bcrypt (au prochain login des utilisateurs).

**En parallèle dès maintenant :**
8. **#9 (A09)** — installer le logging de sécurité pour DÉTECTER toute tentative pendant qu'on corrige.

**Planifié (chantiers, pas des patchs) :**
9. **#4 (A04)** — refonte du flux de reset (design). #6 (A06) selon la CVE. #10 (A10) avant tout déploiement cloud. #8 (A08) signature des webhooks.
```

**Pourquoi ce corrigé est correct :**

- **La priorité ne suit pas le numéro OWASP.** A03 (#3) et A07 (#12) passent devant A02 (#2) parce qu'ils sont **exposés + critiques**, alors que MD5 nécessite d'abord une fuite pour être exploité.
- **L'impact est majoré pour les données d'enfants** : #1 (A01) est en tête bien qu'un contrôle d'accès manquant soit parfois « moyen » ailleurs.
- **Deux constats tombent dans A03** (#3 SQLi et #11 XSS) et **deux dans A07** (#7 rate limit et #12 `alg: none`) — la couverture des 10 catégories est bien assurée par les 12 constats.
- **A09 est classé « base » sur l'impact direct mais traité tôt** : sans logs, on ne voit aucune des attaques pendant la fenêtre de correction. Priorité d'impact ≠ ordre d'exécution.
- Chaque parade est **actionnable et défensive** (« vérifier `ownerId` », « requête paramétrée »), pas une description de l'attaque.

---

## Variante J+30 (fading)

**Même exercice, contraintes ajoutées, sans rouvrir ce corrigé ni le module :**

1. On te donne **5 nouveaux constats** (invente-les ou reprends un vrai projet à toi) et tu produis la carte **en 20 minutes**.
2. Contrainte : pour **chaque** ligne, tu cites **le nom exact de la Cheat Sheet OWASP** correspondante (ex. « SQL Injection Prevention Cheat Sheet ») — sans consulter le site pendant l'exercice, de mémoire.
3. Rends un **plan à 3 actions maximum** : tu dois **justifier ce que tu NE fais PAS en premier** autant que ce que tu fais.

**Critère de réussite :** classification exacte des 5 constats, priorisation cohérente avec Risque = Proba × Impact, et tu sais expliquer à l'oral pourquoi le chantier de design attend.

---

## Application TribuZen

Dans le repo `smaurier/tribuzen`, la carte vit avec le code (elle se met à jour à chaque module sécurité) :

```
tribuzen/
  docs/
    security/
      owasp-risk-map.md      ← livrable de ce lab
      threat-model.md        ← module 00 (A04 Insecure Design)
```

**Le fil rouge :** cette carte est le **tableau de bord** de tout le cours. Chaque module suivant referme une ligne — module 02 ferme A03, module 03 ferme A07, module 04 ferme A01, module 05 ferme A02, module 06 ferme A05, module 09 ferme A06/A08, module 11 ferme A09. Tu mets à jour la colonne « Priorité » en la passant à ✅ au fur et à mesure.

**Commit cible :**
```
docs(security): carte des risques OWASP 2021 + plan de remédiation priorisé
```
