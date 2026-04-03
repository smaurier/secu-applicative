# Lab 02 — Injection : Prévention et Détection

## Objectifs pédagogiques

- Comprendre les différents types d'injection (SQL, XSS, Path Traversal)
- Implémenter des fonctions de sanitisation HTML
- Échapper les entrées pour prévenir l'injection SQL
- Simuler la construction de requêtes paramétrées
- Détecter les payloads XSS courants
- Valider et assainir les chemins de fichiers
- Valider les entrées utilisateur avec des règles configurables

## Concepts clés

L'**injection** (OWASP A03) consiste à envoyer des données non fiables à un interpréteur. Les défenses principales sont :

- **Sanitisation** : nettoyer les entrées dangereuses
- **Requêtes paramétrées** : séparer le code des données
- **Validation d'entrée** : vérifier la conformité des données
- **Encodage de sortie** : encoder les données selon le contexte

## Exercice

Ouvrez `exercise.ts` et implémentez les fonctions suivantes :

1. **`sanitizeHTML`** — Remplacer les caractères dangereux par des entités HTML
2. **`escapeSQL`** — Échapper les caractères dangereux pour SQL
3. **`buildParameterizedQuery`** — Construire une requête paramétrée
4. **`detectXSSPayload`** — Détecter les payloads XSS
5. **`sanitizeFilePath`** — Assainir un chemin de fichier
6. **`validateInput`** — Valider une entrée selon des règles

## Lancement

```bash
npx tsx exercise.ts
```

## Validation

Tous les tests doivent passer au vert. Comparez avec `solution.ts` si besoin.
