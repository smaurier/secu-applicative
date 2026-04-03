# Lab 09 — Sécurité de la Supply Chain

## Objectifs pédagogiques

- Parser et comparer des versions sémantiques (semver)
- Vérifier si une version est dans une plage vulnérable
- Détecter les attaques de typosquatting sur les noms de packages
- Auditer les dépendances contre une base de vulnérabilités
- Calculer un score de risque global

## Concepts clés

La **supply chain** logicielle est un vecteur d'attaque de plus en plus exploité :

- **Semver** : convention de version `MAJOR.MINOR.PATCH` pour gérer les compatibilités
- **Typosquatting** : publication de packages malveillants avec des noms similaires à des packages populaires
- **Audit de dépendances** : comparaison des versions installées avec les bases de vulnérabilités connues
- **Score de risque** : évaluation quantitative du niveau de risque d'un projet

> **Rappel** : Plus de 80% du code d'une application vient de ses dépendances. La sécurité de la supply chain est critique.

## Exercice

Ouvrez `exercise.ts` et implémentez les fonctions suivantes :

1. **`parseSemver`** — Parser une version sémantique
2. **`isVulnerableRange`** — Vérifier si une version est dans une plage vulnérable
3. **`detectTyposquat`** — Détecter les tentatives de typosquatting
4. **`auditDependencies`** — Auditer les dépendances
5. **`calculateRiskScore`** — Calculer un score de risque

## Lancement

```bash
npx tsx exercise.ts
```
