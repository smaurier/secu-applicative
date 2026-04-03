# Lab 10 — Sécurité Infrastructure

## Objectifs pédagogiques

- Auditer un Dockerfile pour détecter les mauvaises pratiques
- Détecter les secrets exposés dans le code source
- Masquer les données sensibles dans les logs
- Valider une configuration d'environnement

## Concepts clés

La **sécurité infrastructure** couvre les pratiques DevSecOps essentielles :

- **Audit Dockerfile** : détection des images non épinglées, exécution root, copie de fichiers sensibles
- **Détection de secrets** : identification des clés API, mots de passe et tokens dans le code
- **Rédaction de logs** : masquage des données sensibles avant journalisation
- **Configuration sécurisée** : validation des variables d'environnement requises et de leurs valeurs

> **Règle d'or** : Les secrets ne doivent JAMAIS être commités dans le code source. Utilisez un gestionnaire de secrets.

## Exercice

Ouvrez `exercise.ts` et implémentez les fonctions suivantes :

1. **`auditDockerfile`** — Auditer un Dockerfile
2. **`detectSecrets`** — Détecter les secrets dans du texte
3. **`redactSensitiveData`** — Masquer les données sensibles dans les logs
4. **`validateEnvironmentConfig`** — Valider une configuration d'environnement

## Lancement

```bash
npx tsx exercise.ts
```
