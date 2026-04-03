# Lab 07 — CORS : Configuration et Validation

## Objectifs pédagogiques

- Comprendre le mécanisme CORS (Cross-Origin Resource Sharing)
- Identifier les requêtes simples vs. les requêtes préflight
- Valider une configuration CORS
- Simuler une requête préflight OPTIONS
- Implémenter le matching d'origines avec patterns wildcard

## Concepts clés

**CORS** est un mécanisme de sécurité du navigateur qui contrôle les requêtes cross-origin :

- **Requête simple** : GET/HEAD/POST avec des en-têtes simples uniquement
- **Requête préflight** : requête OPTIONS envoyée avant la requête réelle
- **Origin matching** : vérification que l'origine de la requête est autorisée
- **Credentials** : les cookies et en-têtes d'authentification nécessitent une configuration spéciale

> **Attention** : Une mauvaise configuration CORS peut exposer votre API à des attaques CSRF ou permettre des fuites de données.

## Exercice

Ouvrez `exercise.ts` et implémentez les fonctions suivantes :

1. **`isSimpleRequest`** — Déterminer si une requête est "simple" (pas de préflight)
2. **`validateCORSConfig`** — Valider une configuration CORS
3. **`simulatePreflight`** — Simuler une requête préflight OPTIONS
4. **`matchOrigin`** — Vérifier si une origine correspond aux origines autorisées

## Lancement

```bash
npx tsx exercise.ts
```
