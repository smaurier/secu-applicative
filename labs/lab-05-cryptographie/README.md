# Lab 05 — Cryptographie Appliquée

## Objectifs pédagogiques

- Comprendre les principes de base du hachage
- Implémenter un chiffrement XOR simple
- Maîtriser l'encodage/décodage Base64
- Comprendre le concept de HMAC (Hash-based Message Authentication Code)
- Implémenter une comparaison en temps constant (prévention des attaques par timing)

## Concepts clés

La **cryptographie** est un pilier fondamental de la sécurité applicative :

- **Hachage** : fonction à sens unique produisant une empreinte de taille fixe
- **Chiffrement symétrique** : même clé pour chiffrer et déchiffrer (ici simulé avec XOR)
- **Base64** : encodage binaire → texte (ce n'est PAS du chiffrement)
- **HMAC** : garantit l'intégrité et l'authenticité d'un message
- **Comparaison en temps constant** : prévient les attaques par analyse de timing

> **Note** : Les implémentations de ce lab sont des simulations pédagogiques. En production, utilisez toujours des bibliothèques cryptographiques éprouvées.

## Exercice

Ouvrez `exercise.ts` et implémentez les fonctions suivantes :

1. **`simpleHash`** — Hachage simple (simulation)
2. **`xorCipher`** — Chiffrement XOR
3. **`xorDecipher`** — Déchiffrement XOR
4. **`base64Encode`** — Encodage Base64
5. **`base64Decode`** — Décodage Base64
6. **`generateHMAC`** — Génération d'un HMAC simulé
7. **`verifyHMAC`** — Vérification d'un HMAC
8. **`compareConstantTime`** — Comparaison en temps constant

## Lancement

```bash
npx tsx exercise.ts
```

## Validation

Tous les tests doivent passer au vert. Comparez avec `solution.ts` si besoin.
