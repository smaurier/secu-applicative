---
titre: "OWASP Top 10 (2021) — panorama défensif"
cours: 14-securite-applicative
notions: ["OWASP Top 10 2021", "A01 Broken Access Control", "A02 Cryptographic Failures", "A03 Injection", "A04 Insecure Design", "A05 Security Misconfiguration", "A06 Vulnerable and Outdated Components", "A07 Identification and Authentication Failures", "A08 Software and Data Integrity Failures", "A09 Security Logging and Monitoring Failures", "A10 SSRF (Server-Side Request Forgery)", "risque = probabilité x impact", "priorisation de remédiation"]
outcomes:
  - "sait nommer les 10 catégories OWASP 2021 (A01 à A10) et le risque de chacune"
  - "sait, pour une vulnérabilité donnée, la classer dans la bonne catégorie OWASP"
  - "sait citer la parade défensive principale de chaque catégorie"
  - "sait prioriser une liste de risques par probabilité x impact pour planifier la remédiation"
prerequis: ["Module 00 — posture sécurité, CIA, defense in depth, moindre privilège"]
next: 02-injection
libs: []
tribuzen: "revue de sécurité transverse de TribuZen — cartographie des risques OWASP sur l'app famille avant durcissement module par module"
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# OWASP Top 10 (2021) — panorama défensif

> **Outcomes — tu sauras FAIRE :** nommer les 10 catégories OWASP 2021, classer une vulnérabilité dans la bonne catégorie, citer la parade défensive principale de chacune, prioriser une liste de risques par probabilité × impact.
> **Difficulté :** :star::star:
>
> **Portée :** ce module est un **panorama** — il donne la carte, pas le détail. Chaque catégorie a son module dédié où l'on durcit vraiment le code : **injection → module 02**, **authentification → module 03**, **autorisation / contrôle d'accès → module 04**, **cryptographie → module 05**, **headers & misconfiguration → module 06**, **supply chain / composants → module 09**. Ici, l'objectif est de **savoir situer un risque** et de **prioriser** ce qu'on va corriger en premier. Angle **100 % défensif** : on montre une faille pour la **comprendre et la corriger**, jamais pour l'exploiter contre un tiers.

## 1. Cas concret d'abord

Tu arrives sur TribuZen (app d'organisation familiale — agendas partagés, listes, **données d'enfants**). La CTO te confie une première mission avant toute nouvelle feature :

> « Fais-moi une **revue de sécurité rapide** de l'app. Je veux une liste des risques classés OWASP, et surtout **par quoi commencer**. On a des données de familles et de mineurs, je ne veux pas de mauvaise surprise. »

Tu ouvres le code et tu notes, pêle-mêle :

1. L'endpoint `GET /api/families/:id/children` renvoie les enfants **sans vérifier** que la famille appartient bien à l'utilisateur connecté (un `familyId` deviné donne accès aux enfants d'une autre famille).
2. Les mots de passe sont hachés en **MD5**.
3. La recherche fait `... WHERE name LIKE '%' + req.query.q + '%'` (concaténation de chaîne dans la requête SQL).
4. Le reset de mot de passe repose sur une **question secrète** (« nom de ton premier animal »).
5. Aucun **header de sécurité** (pas de CSP, `cors({ origin: '*' })`).
6. `npm audit` remonte **3 vulnérabilités dont 1 critique**.
7. Pas de **rate limiting** sur `/api/login`.
8. Les webhooks entrants ne **vérifient aucune signature**.
9. **Aucun log** des échecs d'authentification ni des accès refusés.
10. Un endpoint « aperçu de lien » fait `axios.get(url)` sur une **URL fournie par l'utilisateur**.

Dix problèmes, dix catégories OWASP — ce n'est pas un hasard. À la fin de ce module, tu sauras **coller une étiquette A0x sur chacun**, dire **la parade**, et surtout répondre à la vraie question de la CTO : **par quoi commencer ?**

---

## 2. Théorie complète, concise

### 2.0 Ce qu'est l'OWASP Top 10 (et ce qu'il n'est pas)

L'**OWASP** (Open Worldwide Application Security Project) est une fondation à but non lucratif. Son document phare, le **Top 10**, est une **liste de sensibilisation** : les dix **catégories de risques** de sécurité web les plus critiques, révisée tous les 3-4 ans (**édition de référence 2021** ; une Release Candidate 2025 est en cours de publication — ce module reste basé sur l'édition 2021, stable et citée en entretien). Chaque entrée regroupe plusieurs CWE (types de faiblesses).

> Ce n'est **pas** une checklist exhaustive ni une certification. C'est un **socle commun** : le vocabulaire minimal qu'un dev backend doit partager avec les auditeurs. Le référentiel exhaustif pour vérifier une app est l'**ASVS**, et les recettes détaillées sont dans les **Cheat Sheets** OWASP (voir §fin).

Une catégorie OWASP se lit toujours en deux temps, et c'est **le second qui compte pour nous** :
- **le risque** — ce qui peut mal tourner ;
- **la parade défensive** — ce qu'on met en place pour l'empêcher ou le détecter.

### 2.1 Les 10 catégories 2021 (liste officielle exacte)

Ordre officiel = par prévalence / criticité constatée dans les données OWASP 2021.

| Code | Catégorie officielle | Le risque, en une phrase | Parade défensive principale | Détail |
|------|----------------------|--------------------------|------------------------------|--------|
| **A01** | Broken Access Control | Un utilisateur accède à des ressources ou actions qui ne lui sont pas autorisées. | **Deny by default**, vérifier l'autorisation **côté serveur** à chaque accès. | module 04 |
| **A02** | Cryptographic Failures | Des données sensibles sont exposées faute de chiffrement / hachage corrects. | Hachage fort des mots de passe, TLS partout, clés hors du code. | module 05 |
| **A03** | Injection | Une entrée non fiable est interprétée comme du code/commande (SQLi, XSS…). | **Requêtes paramétrées**, échappement contextuel de la sortie, validation. | module 02 |
| **A04** | Insecure Design | La faille est dans la **conception**, pas dans l'implémentation. | **Threat modeling** en amont, patterns sûrs, limites de ressources. | ce module + 00 |
| **A05** | Security Misconfiguration | Config par défaut / permissive : headers absents, verbosité, comptes par défaut. | Durcissement reproductible, surface minimale, headers de sécurité. | module 06 |
| **A06** | Vulnerable and Outdated Components | Une dépendance a une vulnérabilité **connue** et publique. | Inventaire (SBOM), `npm audit`, veille CVE, mise à jour. | module 09 |
| **A07** | Identification and Authentication Failures | L'authentification peut être contournée / brute-forcée. | MFA, mots de passe forts, **rate limiting**, sessions gérées serveur. | module 03 |
| **A08** | Software and Data Integrity Failures | On fait confiance à du code/donnée dont l'intégrité n'est pas vérifiée. | Signatures, **SRI**, CI/CD durci, pas de désérialisation non fiable. | module 09 |
| **A09** | Security Logging and Monitoring Failures | Sans logs ni alertes, les attaques passent inaperçues. | Logger les événements de sécurité, centraliser, **alerter**. | module 11 |
| **A10** | Server-Side Request Forgery (SSRF) | Le serveur va chercher une URL fournie par l'utilisateur → accès interne. | **Allow-list** de destinations, bloquer IP privées & métadonnées cloud. | module 08 / 10 |

> **À mémoriser exactement.** Les titres ci-dessus sont les intitulés officiels OWASP 2021 (source : owasp.org/Top10/2021). Ne les paraphrase pas en entretien : « A03 Injection », « A10 SSRF », etc.

### 2.2 Ce qui a changé depuis 2017 (pour la culture, pas par cœur)

Trois évolutions racontent l'histoire des menaces modernes :

- **A01 Broken Access Control** est **monté au 1er rang** (5ᵉ en 2017) — c'est aujourd'hui le risque le plus répandu.
- **A04 Insecure Design** est **nouveau** : OWASP reconnaît qu'une implémentation parfaite ne rattrape **jamais** un design non sûr.
- **A10 SSRF** est **nouveau** aussi, poussé par le cloud (métadonnées d'instance, réseaux internes).

`XSS` a fusionné dans **A03 Injection**, et `XXE` dans **A05 Security Misconfiguration**.

### 2.3 Comment on **priorise** (le cœur du métier)

Connaître les 10 catégories ne suffit pas : en revue, on te demandera **par quoi commencer**. La règle universelle :

> **Risque = Probabilité × Impact.**

- **Probabilité** — à quel point c'est facile/probable d'être touché (faille exposée sur Internet ? exploit public ? authentification requise ?).
- **Impact** — ce qu'on perd si ça arrive (fuite de données d'enfants = impact maximal sur TribuZen ; défiguration d'une page marketing = faible).

On classe ensuite en niveaux : **Critique / Haute / Moyenne / Base**. Deux principes défensifs orientent le tri :

1. **Ce qui protège des données sensibles passe devant.** Sur TribuZen, tout ce qui touche aux enfants et aux comptes familiaux monte d'un cran.
2. **À impact égal, on corrige d'abord le facile et exposé.** Ajouter `helmet()` ou un rate limiter coûte une heure ; refondre un design non sûr (A04) coûte des semaines — mais reste à planifier.

### 2.4 Angle défensif : la posture, pas l'exploit

Tout au long de ce cours, on regarde une faille pour **la refermer**. Concrètement, chaque catégorie se traite avec **le même réflexe en trois temps** :

1. **Détecter** — où, dans mon code, cette catégorie peut-elle mordre ? (revue, `npm audit`, tests).
2. **Prévenir** — la parade par défaut (deny by default, requête paramétrée, TLS, allow-list…).
3. **Surveiller** — logguer et alerter pour voir si on est attaqué (A09 est transverse : il rend les 9 autres **détectables**).

---

## 3. Worked examples

### Exemple 1 — Étiqueter les 10 problèmes de TribuZen

On reprend la liste du §1 et on colle l'étiquette OWASP + la parade. **C'est exactement l'exercice de revue attendu en poste.**

| # | Constat TribuZen | Catégorie | Parade défensive (le « quoi faire ») |
|---|------------------|-----------|--------------------------------------|
| 1 | `/families/:id/children` sans vérif de propriété | **A01** Broken Access Control | Vérifier côté serveur que `family.ownerId === req.user.id` ; deny by default. |
| 2 | Mots de passe en **MD5** | **A02** Cryptographic Failures | Re-hacher avec **bcrypt/argon2**, jamais MD5/SHA1 pour un mot de passe. |
| 3 | SQL par **concaténation** de `req.query.q` | **A03** Injection | **Requête paramétrée** (`WHERE name LIKE $1`), pas de concaténation. |
| 4 | Reset via **question secrète** | **A04** Insecure Design | Repenser le flux : **token à usage unique, expirant**, envoyé par email. |
| 5 | Pas de headers, `cors({ origin: '*' })` | **A05** Security Misconfiguration | `helmet()`, CORS restreint à l'origine du front, pas de stack trace en prod. |
| 6 | `npm audit` : 1 critique | **A06** Vulnerable Components | Mettre à jour / `overrides`, veille CVE (Dependabot). |
| 7 | Pas de rate limiting sur `/login` | **A07** Auth Failures | Rate limiter + verrou temporaire de compte, MFA. |
| 8 | Webhooks sans **signature** | **A08** Integrity Failures | Vérifier une signature HMAC en **timing-safe** avant de traiter. |
| 9 | Aucun log des échecs d'auth | **A09** Logging Failures | Logger login/échecs/accès refusés en JSON, centraliser, alerter. |
| 10 | « Aperçu de lien » `axios.get(url)` | **A10** SSRF | **Allow-list** de domaines, bloquer IP privées & `169.254.169.254`. |

> Remarque : le problème #2 (MD5) touche A02 **et** A07 (mécanisme d'auth faible). Une même faille peut relever de plusieurs catégories — on retient la **dominante** (ici le défaut cryptographique) et on note la seconde.

### Exemple 2 — Prioriser pour répondre « par quoi on commence ? »

On applique **Risque = Probabilité × Impact**, en majorant l'impact quand des **données d'enfants** sont en jeu.

| Rang | # / Catégorie | Probabilité | Impact | Niveau | Pourquoi ce rang |
|------|---------------|-------------|--------|--------|------------------|
| 1 | #1 A01 (accès enfants) | Haute (ID devinable, exposé) | **Critique** (données mineurs) | 🔴 Critique | Exposé + données les plus sensibles → **on commence ici**. |
| 2 | #3 A03 (SQLi) | Haute (endpoint public) | Critique (base entière) | 🔴 Critique | Une injection peut tout compromettre. |
| 3 | #2 A02 (MD5) | Moyenne (nécessite une fuite) | Critique (tous les comptes) | 🟠 Haute | À corriger vite, mais après avoir fermé l'accès direct. |
| 4 | #7 A07 (pas de rate limit) | Haute | Haute (prise de compte) | 🟠 Haute | Parade **rapide** (1 middleware) → excellent ratio effort/gain. |
| 5 | #5 A05 (headers/CORS) | Haute | Moyenne | 🟡 Moyenne | `helmet()` : quelques minutes, à faire tout de suite aussi. |
| 6 | #6 A06 (dépendance critique) | Moyenne | Variable | 🟡 Moyenne | Dépend de la CVE ; `npm audit fix` d'abord. |
| 7 | #10 A10 (SSRF) | Moyenne | Haute (métadonnées cloud) | 🟡 Moyenne | Critique si déployé en cloud → allow-list. |
| 8 | #8 A08 (webhooks) | Faible/Moyenne | Haute | 🟡 Moyenne | Vérifier la signature avant traitement. |
| 9 | #4 A04 (design reset) | Moyenne | Haute | 🔵 Base | Vrai chantier de **conception** → planifier, pas patcher. |
| 10 | #9 A09 (logs) | — | — (transverse) | 🔵 Base mais **prioritaire au sens support** | Sans logs, on ne **voit** aucune des 9 autres → à installer en parallèle. |

**Réponse à la CTO :** « On ferme d'abord l'accès direct aux enfants (A01) et l'injection SQL (A03) — exposés et critiques. En parallèle, deux quick wins à effort quasi nul : `helmet()` (A05) et le rate limiter sur `/login` (A07). On rehash les mots de passe (A02) dans la foulée. Le reste est planifié ; le reset par question secrète (A04) est un chantier de refonte, pas un patch. Et on **installe le logging de sécurité (A09) dès maintenant** pour détecter toute tentative pendant qu'on corrige. »

---

## 4. Pièges & misconceptions

### PIÈGE #1 — Croire que le Top 10 est une checklist « fait / pas fait »

Le Top 10 est un document de **sensibilisation**, pas un standard de vérification. Cocher les 10 cases ne veut pas dire « app sécurisée ». Pour une vérification structurée, on utilise l'**ASVS** (Application Security Verification Standard). Le Top 10 sert à **parler le même langage** et à prioriser, rien de plus.

### PIÈGE #2 — Confondre A01 (autorisation) et A07 (authentification)

- **A07 Authentication** = « **es-tu bien qui tu prétends être ?** » (login, mot de passe, MFA, sessions).
- **A01 Access Control** = « **une fois identifié, as-tu le droit de faire ça ?** » (accéder à *cette* famille, supprimer *cet* enfant).

L'endpoint TribuZen #1 est authentifié (l'utilisateur est connecté) mais **mal autorisé** (il accède à une autre famille) → c'est **A01**, pas A07.

### PIÈGE #3 — Penser que « le framework me protège » dispense de tout

Un ORM protège de beaucoup d'injections SQL **si on l'utilise correctement** (une requête raw concaténée reste vulnérable). Vue/React échappent le HTML par défaut **sauf** `v-html` / `dangerouslySetInnerHTML`. Le framework **réduit** la surface ; il ne remplace pas la revue. La misconfiguration (A05) naît justement de la confiance aveugle dans les défauts.

### PIÈGE #4 — Négliger A09 parce qu'il « n'empêche pas d'attaque »

A09 (Logging & Monitoring) ne bloque effectivement rien **au moment** de l'attaque. Mais sans lui, une brèche reste invisible en moyenne des mois. C'est le prérequis pour **détecter** les 9 autres. Le classer « base » sur l'impact direct mais le **traiter tôt** n'est pas contradictoire : c'est un socle, pas une rustine.

### PIÈGE #5 — Prioriser par le numéro de catégorie

A01 > A10 dans la liste **ne veut pas dire** « corrige A01 avant A10 chez toi ». L'ordre OWASP est une **prévalence mondiale moyenne**. Ta priorité dépend de **ton** exposition et de **ton** impact (Risque = Proba × Impact). Sur une app cloud, un SSRF (A10) peut être ta priorité n°1.

### PIÈGE #6 — Écrire un exploit « pour tester »

Angle défensif : on **ne rédige pas** de payload d'attaque prêt à lancer contre un système qu'on ne possède pas (c'est illégal et hors sujet). On reproduit une faille **dans son propre bac à sable** pour la **comprendre et la corriger**, et on teste avec des outils dédiés (SAST/DAST — module 11) sur **ses** environnements.

---

## 5. Ancrage TribuZen

Ce module est le **point de départ de tout le cours sécurité** appliqué à TribuZen. Le livrable concret est une **cartographie des risques** — un document vivant qui pilote l'ordre des modules suivants.

TribuZen manipule des **données de familles et de mineurs** : la CNIL et le RGPD imposent une vigilance renforcée. Concrètement, l'impact d'une fuite est **toujours majoré**, ce qui remonte mécaniquement les catégories touchant à ces données (A01, A02, A03) en tête de priorité.

Fichier cible dans `smaurier/tribuzen` (artefact de revue, versionné avec le code) :

```
tribuzen/
  docs/
    security/
      owasp-risk-map.md      ← la cartographie du lab (constat → A0x → parade → priorité)
      threat-model.md        ← issu du module 00 (Insecure Design / A04)
```

Le tableau de l'Exemple 2 **est** la première version de `owasp-risk-map.md`. Chaque module suivant du cours en referme une ligne :
- module 02 → ferme la ligne **A03** (injection),
- module 03 → **A07** (auth), module 04 → **A01** (accès),
- module 05 → **A02** (crypto), module 06 → **A05** (headers/misconfig),
- module 09 → **A06/A08** (supply chain & intégrité), module 11 → **A09** (audit & logs).

> Ainsi le fil rouge n'est pas décoratif : la carte OWASP se **vide** au fil du cours, chaque risque étant durci dans son module dédié.

---

## 6. Points clés

1. L'OWASP Top 10 (2021) = **10 catégories de risques** web, document de **sensibilisation** (pas une checklist ni une certif).
2. Liste exacte à connaître : **A01** Broken Access Control, **A02** Cryptographic Failures, **A03** Injection, **A04** Insecure Design, **A05** Security Misconfiguration, **A06** Vulnerable and Outdated Components, **A07** Identification and Authentication Failures, **A08** Software and Data Integrity Failures, **A09** Security Logging and Monitoring Failures, **A10** SSRF.
3. **A01** est le risque n°1 en 2021 (contrôle d'accès) ; **A04** (Insecure Design) et **A10** (SSRF) sont les **nouveautés** 2021.
4. Chaque catégorie se lit **risque → parade défensive** ; c'est la parade qui nous intéresse.
5. Ne pas confondre **A07 authentification** (« qui es-tu ? ») et **A01 autorisation** (« as-tu le droit ? »).
6. On priorise par **Risque = Probabilité × Impact**, pas par le numéro de catégorie — et on majore l'impact quand des données sensibles (enfants) sont en jeu.
7. **A09 (logging)** n'empêche pas une attaque mais rend les 9 autres **détectables** → socle à installer tôt.
8. Posture **défensive** : reproduire une faille dans **son** bac à sable pour la corriger, jamais l'exploiter chez un tiers.

---

## 7. Seeds Anki

```
Combien de catégories dans l'OWASP Top 10, et à quoi sert-il ?|10 catégories de risques de sécurité web. C'est un document de SENSIBILISATION (vocabulaire commun + priorisation), pas une checklist exhaustive ni une certification — pour vérifier une app, on utilise l'ASVS.
Quelle est la catégorie OWASP n°1 en 2021 et pourquoi ?|A01 Broken Access Control — montée du 5e (2017) au 1er rang car c'est le risque le plus répandu : un utilisateur accède à des ressources/actions non autorisées.
Quelles sont les deux nouvelles catégories de l'OWASP Top 10 2021 ?|A04 Insecure Design (la faille est dans la conception, pas l'implémentation) et A10 SSRF (Server-Side Request Forgery), poussé par le cloud.
Différence entre A07 et A01 en une phrase ?|A07 Authentication = "es-tu bien qui tu prétends être ?" (login/MFA/session). A01 Access Control = "une fois identifié, as-tu le droit de faire cette action sur cette ressource ?".
Quelle formule sert à prioriser les vulnérabilités, et pourquoi pas l'ordre A01..A10 ?|Risque = Probabilité x Impact. L'ordre OWASP est une prévalence mondiale moyenne ; la priorité réelle dépend de TON exposition et de TON impact (ex: SSRF peut être n°1 en cloud).
Cite la parade défensive principale de A03 Injection.|Requêtes paramétrées (jamais de concaténation de chaîne), plus échappement contextuel de la sortie et validation des entrées. Détail au module 02.
Pourquoi installer A09 (logging & monitoring) tôt même s'il "n'empêche rien" ?|Il ne bloque pas l'attaque au moment T, mais sans logs une brèche reste invisible des mois. C'est le socle qui rend les 9 autres catégories DÉTECTABLES.
En posture défensive, que fait-on avec une faille — et que ne fait-on jamais ?|On la reproduit dans son PROPRE bac à sable pour la comprendre et la corriger (détecter → prévenir → surveiller). On n'écrit jamais de payload d'attaque prêt à lancer contre un système tiers.
```

---

## Pont vers le lab

> Lab associé : `labs/lab-01-owasp-top10/README.md`. Exercice **défensif** : cartographier les risques OWASP sur TribuZen (constat → catégorie A0x → parade), puis les **prioriser** par Risque = Probabilité × Impact pour produire `owasp-risk-map.md`. README-only, corrigé commenté, coach en session.
