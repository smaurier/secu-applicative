# Lab 04 — Autorisation : RBAC et Permissions

## Objectifs pédagogiques

- Implémenter un système de contrôle d'accès basé sur les rôles (RBAC)
- Gérer l'héritage de rôles
- Détecter les vulnérabilités IDOR (Insecure Direct Object Reference)
- Implémenter un limiteur de débit (rate limiter)
- Filtrer les champs sensibles selon le rôle de l'utilisateur

## Concepts clés

L'**autorisation** (OWASP A01 — Broken Access Control) détermine ce qu'un utilisateur authentifié a le droit de faire :

- **RBAC** : les permissions sont attribuées à des rôles, les utilisateurs héritent des permissions via leurs rôles
- **IDOR** : accès direct à des objets sans vérification d'appartenance
- **Rate Limiting** : limitation du nombre de requêtes par utilisateur
- **Filtrage de données** : ne retourner que les champs autorisés

## Exercice

Ouvrez `exercise.ts` et implémentez les fonctions suivantes :

1. **`createRBACSystem`** — Système RBAC avec héritage de rôles
2. **`checkIDOR`** — Vérification d'accès IDOR
3. **`createRateLimiter`** — Limiteur de débit à fenêtre glissante
4. **`filterSensitiveFields`** — Filtrage de champs selon le rôle

## Lancement

```bash
npx tsx exercise.ts
```

## Validation

Tous les tests doivent passer au vert. Comparez avec `solution.ts` si besoin.
