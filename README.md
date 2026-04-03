# 18 — Sécurité Applicative

> Protéger les applications web modernes : OWASP Top 10, authentification, cryptographie, sécurité des APIs et de la supply chain.

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
