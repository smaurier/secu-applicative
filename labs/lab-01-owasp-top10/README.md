# Lab 01 — OWASP Top 10 : Identifier les vulnérabilités

## Objectifs pédagogiques

- Comprendre les 10 catégories de vulnérabilités OWASP
- Savoir classifier une vulnérabilité selon sa catégorie OWASP
- Évaluer le risque associé à une vulnérabilité
- Prioriser les vulnérabilités pour la remédiation
- Détecter des patterns d'injection SQL simples
- Générer un rapport synthétique de vulnérabilités

## Concepts clés

Le **OWASP Top 10** est une référence standard pour les vulnérabilités de sécurité les plus critiques des applications web :

| Code | Catégorie |
|------|-----------|
| A01 | Broken Access Control |
| A02 | Cryptographic Failures |
| A03 | Injection |
| A04 | Insecure Design |
| A05 | Security Misconfiguration |
| A06 | Vulnerable and Outdated Components |
| A07 | Identification and Authentication Failures |
| A08 | Software and Data Integrity Failures |
| A09 | Security Logging and Monitoring Failures |
| A10 | Server-Side Request Forgery (SSRF) |

## Exercice

Ouvrez `exercise.ts` et implémentez les fonctions suivantes :

1. **`classifyVulnerability`** — Classifier une vulnérabilité selon sa description
2. **`assessRisk`** — Calculer un score de risque
3. **`prioritizeVulnerabilities`** — Trier les vulnérabilités par priorité
4. **`detectSQLInjection`** — Détecter des patterns d'injection SQL
5. **`generateReport`** — Générer un rapport synthétique

## Lancement

```bash
npx tsx exercise.ts
```

## Validation

Tous les tests doivent passer au vert. Comparez avec `solution.ts` si besoin.
