# Lab 08 — Sécurité des APIs

## Objectifs pédagogiques

- Implémenter un rate limiter avec fenêtre glissante
- Valider les entrées d'une API selon un schéma
- Filtrer les champs sensibles dans les réponses
- Détecter les attaques par profondeur dans les requêtes GraphQL
- Générer des clés d'idempotence

## Concepts clés

La **sécurité des APIs** repose sur plusieurs mécanismes de protection :

- **Rate limiting** : limite le nombre de requêtes par client pour prévenir les abus
- **Validation d'entrées** : vérifie que les données reçues respectent un schéma attendu
- **Filtrage de réponse** : ne retourne que les champs autorisés (évite les fuites de données)
- **Protection GraphQL** : détecte les requêtes imbriquées excessivement (attaque par profondeur)
- **Idempotence** : garantit qu'une même requête produit le même résultat

> **Bonne pratique** : Appliquez le principe du moindre privilège — ne retournez que les données nécessaires.

## Exercice

Ouvrez `exercise.ts` et implémentez les fonctions suivantes :

1. **`createRateLimiter`** — Rate limiter à fenêtre glissante
2. **`validateAPIInput`** — Validation d'entrées selon un schéma
3. **`filterResponse`** — Filtrage des champs dans une réponse
4. **`detectGraphQLDepthAttack`** — Détection de profondeur excessive
5. **`generateIdempotencyKey`** — Génération de clé d'idempotence

## Lancement

```bash
npx tsx exercise.ts
```
