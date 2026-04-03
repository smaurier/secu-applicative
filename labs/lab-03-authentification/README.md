# Lab 03 — Authentification Sécurisée

## Objectifs pédagogiques

- Comprendre le principe du hachage de mots de passe avec sel (salt)
- Simuler la vérification d'un mot de passe haché
- Comprendre la structure d'un JSON Web Token (JWT)
- Vérifier l'expiration d'un token
- Évaluer la robustesse d'un mot de passe

## Concepts clés

L'**authentification** (OWASP A07) est le processus de vérification de l'identité d'un utilisateur. Les bonnes pratiques incluent :

- **Hachage avec sel** : ne jamais stocker les mots de passe en clair
- **JWT** : tokens signés pour l'authentification stateless
- **Politique de mots de passe** : imposer une complexité minimale
- **Protection contre le brute force** : limiter les tentatives

> **Note** : Ce lab utilise des simulations simplifiées. En production, utilisez toujours des bibliothèques cryptographiques éprouvées (bcrypt, argon2, etc.).

## Exercice

Ouvrez `exercise.ts` et implémentez les fonctions suivantes :

1. **`simulateHash`** — Simuler un hachage de mot de passe
2. **`verifyPassword`** — Vérifier un mot de passe haché
3. **`generateSalt`** — Générer un sel déterministe
4. **`parseJWT`** — Parser un token JWT
5. **`isTokenExpired`** — Vérifier l'expiration d'un token
6. **`checkPasswordStrength`** — Évaluer la robustesse d'un mot de passe

## Lancement

```bash
npx tsx exercise.ts
```

## Validation

Tous les tests doivent passer au vert. Comparez avec `solution.ts` si besoin.
