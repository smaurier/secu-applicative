# Review — `SessionToken.ts`

À remplir en lisant UNIQUEMENT `src/SessionToken.ts` — rien d'autre, pas encore les tests.
Le correcteur lit ce fichier avant ton code.

1. **`verifySession` vérifie la signature, puis retourne `userId`.** Où, dans cette
   fonction, `expiresAt` (le troisième champ du token, censé porter une date d'expiration)
   est-il utilisé pour décider si le token est encore valide ?

2. **`if (sig !== expectedSig) return null;`** — `!==` compare deux chaînes de caractères.
   Cherche (module 05, cryptographie) ce qu'un attaquant peut apprendre d'une comparaison de
   chaînes non protégée contre les attaques temporelles, même si c'est difficile à exploiter
   en pratique sur ce lab précis. Quelle fonction de `node:crypto` protège contre ça ?

3. **Deux failles, deux catégories OWASP différentes** (revois le module 01) — nomme-les.

4. Pour chacune, la correction minimale, en une phrase.
