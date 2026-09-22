# 18 — Sécurité Applicative

![VitePress](https://img.shields.io/badge/-VitePress-646CFF?style=flat-square&logo=vite&logoColor=white)
![TypeScript](https://img.shields.io/badge/-TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)
[![fullstack-autotraining](https://img.shields.io/badge/curriculum-fullstack--autotraining-4C1?style=flat-square)](https://github.com/smaurier/fullstack-autotraining)

> Protéger les applications web modernes : OWASP Top 10, authentification, cryptographie, sécurité des APIs et de la supply chain.

<!-- labs-gestes:start -->
## Labs — refonte du 22/09/2026 : un lab = un geste métier complet

> Règle qualité 5 du parcours : chaque lab est **un geste métier complet**, sous deux formes — **Zéro** (construire de zéro un artefact réel et entier) ou **Intervention** (modifier de l'existant avec consommateurs, findings avant code, non-régression). Un lab n'entre en file qu'avec un **oracle exécutable** (`src/` starter · `test/` · `solution/` séparée). Les labs historiques de ce cours (un concept par lab, sans oracle) restent dans `labs/` jusqu'à remplacement et **ne sont plus la file**. Cible détaillée : [`docs/gestes-complets.md`](../docs/gestes-complets.md). État : **3/4 avec oracle**.

| # | Lab | Forme | Geste | Oracle |
|---|-----|-------|-------|--------|
| 01 | [`lab-01-oidc-pkce-webauthn-de-zero`](labs/lab-01-oidc-pkce-webauthn-de-zero/README.md) | Zéro | PKCE RFC 7636 complet (vecteur de test officiel) ; OIDC/WebAuthn documentés, hors oracle (besoin d'un vrai IdP/navigateur) | ✅ vérifié |
| 02 | [`lab-02-audit-owasp`](labs/lab-02-audit-owasp/README.md) | Intervention | auditer une appli, corriger le top 3 trouvé | ✅ vérifié |
| 03 | [`lab-03-csp-sur-un-front-existant`](labs/lab-03-csp-sur-un-front-existant/README.md) | Intervention | sans rien casser | ✅ vérifié |
| 04 | `lab-04-relire-une-pr-auth` | Intervention | findings avant vérité | · à écrire |

<!-- labs-gestes:end -->

## Objectifs pédagogiques

À l'issue de ce module, l'apprenant sera capable de :

- Identifier et prévenir les vulnérabilités du OWASP Top 10
- Implémenter une authentification et une autorisation sécurisées (JWT, OAuth2, RBAC)
- Appliquer les bonnes pratiques de cryptographie (hashing, chiffrement, TLS)
- Sécuriser les en-têtes HTTP (CSP, CORS, HSTS, X-Frame-Options)
- Protéger les APIs REST et GraphQL contre les attaques courantes
- Auditer la supply chain (dépendances, lockfiles, SCA)
- Mettre en place une stratégie de sécurité défensive (rate limiting, WAF, logging)

## Prérequis

- JavaScript/TypeScript solides (modules 03-04)
- Connaissances HTTP et APIs REST (module 09)
- Node.js et Express/NestJS (module 07)
- Bases de données (module 08)

## Structure du cours

```
18-securite-applicative/
├── modules/           # 12 chapitres théoriques (Markdown)
├── labs/              # 10 ateliers pratiques (TypeScript)
├── quizzes/           # 12 quiz interactifs (HTML)
├── glossaire.md       # Termes clés sécurité
└── index.md           # Page d'accueil VitePress
```

## Parcours recommandé

### Phase 1 — Fondamentaux (modules 00-03)
| Module | Sujet | Lab | Quiz |
|--------|-------|-----|------|
| 00 | Introduction à la sécurité applicative | — | quiz-00 |
| 01 | OWASP Top 10 : vue d'ensemble | lab-01 | quiz-01 |
| 02 | Injection (SQL, XSS, Command Injection) | lab-02 | quiz-02 |
| 03 | Authentification & gestion de sessions | lab-03 | quiz-03 |

### Phase 2 — Défenses avancées (modules 04-07)
| Module | Sujet | Lab | Quiz |
|--------|-------|-----|------|
| 04 | Autorisation : RBAC, ABAC, ACL | lab-04 | quiz-04 |
| 05 | Cryptographie appliquée | lab-05 | quiz-05 |
| 06 | En-têtes HTTP de sécurité | lab-06 | quiz-06 |
| 07 | CORS en profondeur | lab-07 | quiz-07 |

### Phase 3 — Sécurité système (modules 08-11)
| Module | Sujet | Lab | Quiz |
|--------|-------|-----|------|
| 08 | Sécurité des APIs (REST & GraphQL) | lab-08 | quiz-08 |
| 09 | Supply chain & dépendances | lab-09 | quiz-09 |
| 10 | Sécurité infrastructure (Docker, secrets) | lab-10 | quiz-10 |
| 11 | Audit, pentest & conformité | — | quiz-11 |

## Lancer le site de documentation

```bash
cd 18-securite-applicative
pnpm install
pnpm docs:dev
```

## Exécuter un lab

```bash
# Exercice (à compléter)
pnpm lab:01

# Solution
pnpm solution:01
```

## Temps estimé

~50 heures (théorie + pratique + quiz)
