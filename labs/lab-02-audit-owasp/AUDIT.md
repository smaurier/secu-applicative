# Audit — `UserAccountService.ts`

À remplir AVANT toute correction, en lisant UNIQUEMENT `src/UserAccountService.ts`. Le
correcteur lit ce fichier avant ton code.

1. **A02 — Cryptographic Failures.** `createHash("sha256").update(password).digest("hex")`
   — deux utilisateurs avec le même mot de passe auront-ils le même hash stocké ? Pourquoi
   c'est un problème concret (indice : table arc-en-ciel).

2. **A04 — Insecure Design.** Que se passe-t-il si quelqu'un s'inscrit avec le mot de passe
   `"a"` ? Rien dans ce fichier ne l'en empêche — quelle politique minimale manque ?

3. **A07 — Identification and Authentication Failures.** Un script peut-il appeler
   `login(username, motDePasseAuHasard)` en boucle, sans limite ? Que peut faire un
   attaquant avec ça ?

4. **Priorisation.** Pour chacune des trois, estime probabilité × impact (haut/moyen/bas).
   Dans quel ordre les corrigerais-tu si tu n'avais le temps que pour deux sur trois ?
