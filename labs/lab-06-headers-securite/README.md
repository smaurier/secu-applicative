# Lab 06 — En-têtes HTTP de Sécurité

## Objectifs pédagogiques

- Comprendre le rôle des en-têtes HTTP de sécurité
- Parser et construire une Content-Security-Policy (CSP)
- Auditer la présence des en-têtes de sécurité essentiels
- Construire un en-tête HSTS (HTTP Strict Transport Security)
- Détecter les configurations CSP dangereuses

## Concepts clés

Les **en-têtes HTTP de sécurité** constituent une couche de défense essentielle :

- **Content-Security-Policy (CSP)** : contrôle les sources de contenu autorisées
- **Strict-Transport-Security (HSTS)** : force l'utilisation de HTTPS
- **X-Content-Type-Options** : empêche le sniffing MIME
- **X-Frame-Options** : protège contre le clickjacking
- **Referrer-Policy** : contrôle les informations envoyées via le header Referer
- **Permissions-Policy** : restreint les fonctionnalités du navigateur

> **Note** : Ces en-têtes sont simples à configurer mais souvent oubliés. Un audit régulier est recommandé.

## Exercice

Ouvrez `exercise.ts` et implémentez les fonctions suivantes :

1. **`parseCSP`** — Parser une chaîne CSP en directives structurées
2. **`buildCSP`** — Reconstruire une chaîne CSP depuis des directives
3. **`auditHeaders`** — Auditer la présence des en-têtes de sécurité
4. **`buildHSTS`** — Construire un en-tête HSTS
5. **`isCSPSafe`** — Vérifier qu'une CSP ne contient pas de patterns dangereux

## Lancement

```bash
npx tsx exercise.ts
```
