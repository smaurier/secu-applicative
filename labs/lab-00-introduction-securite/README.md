<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Lab 00 — Introduction à la sécurité : modèle de menace de TribuZen

> **Outcome :** à la fin, tu sais dresser un **modèle de menace défensif** d'une application réelle — cartographier sa surface d'attaque, lister les menaces avec STRIDE, et prioriser les risques par (impact × probabilité).
> **Vrai outil :** un vrai document versionné — `docs/security/threat-model.md` dans le repo `smaurier/tribuzen` (Markdown + Git, comme un ADR). Pas de harnais, pas de test-runner.
> **Feedback :** le coach valide le document en session — la qualité se juge à la pertinence des menaces trouvées et de la priorisation, pas à un « vert automatique ».
> **⚠️ Cadre défensif strict :** on modélise **notre propre** application pour la **protéger**. Aucune attaque, aucun scan de système tiers. On produit une analyse, pas un exploit.

---

## Énoncé

TribuZen gère des familles : **fiches d'enfants** (prénom, date de naissance, école, allergies/santé, photos), **agenda partagé**, **messagerie entre parents**, **authentification** des parents. Données mineures sensibles → enjeu RGPD réel.

Ta mission : produire le **premier modèle de menace** du produit, dans un document qui servira de référence à toute l'équipe. Trois livrables dans un seul fichier `threat-model.md` :

1. **Cartographie de la surface d'attaque** — la liste structurée de tout ce qui est exposé.
2. **Analyse STRIDE** — pour les 2 composants les plus sensibles, les menaces par catégorie.
3. **Registre de risques priorisé** — un tableau trié par criticité, avec la contre-mesure envisagée (et le module du cours qui la traite).

Périmètre système fourni (à modéliser) :

```
[ Navigateur parent ]
        │ HTTPS
        ▼
[ API TribuZen ] ── routes :
   POST /api/auth/login          (authentification)
   GET  /api/children/:id        (fiche enfant — donnée sensible)
   POST /api/children/:id/photo  (upload photo enfant)
   GET  /api/messages?familyId=  (messagerie famille)
   POST /api/agenda              (événement agenda)
        │
        ▼
[ Base de données PostgreSQL ]  (children, families, messages, users)
        │
        └── dépendances npm, secrets (.env), logs
```

**Pas de gap-fill.** Tu écris le document à partir du squelette ci-dessous.

### Starter — `docs/security/threat-model.md`

```markdown
# Modèle de menace — TribuZen (v1)

> Document défensif. Objectif : identifier et prioriser les risques pour les corriger.
> Rejoué à chaque nouvelle fonctionnalité. Auteur : <toi>. Date : <date>.

## 1. Sur quoi travaille-t-on ? (surface d'attaque)
<!-- Points d'entrée réseau, entrées de données, dépendances, secrets, humains -->

## 2. Qu'est-ce qui peut mal tourner ? (STRIDE)
<!-- Pour /api/children/:id et POST /api/children/:id/photo -->

## 3. Registre de risques priorisé
<!-- Tableau : Risque | Impact | Probabilité | Criticité | Contre-mesure | Module -->

## 4. A-t-on fait un travail suffisant ?
<!-- Comment on vérifiera, quand on rejouera ce modèle -->
```

---

## Étapes (en friction)

1. **Cartographie la surface d'attaque** (section 1). Classe en 5 familles : points d'entrée réseau, entrées de données (params, corps, en-têtes, cookies, fichiers), dépendances, secrets/config, facteur humain. Sois exhaustif sur les routes fournies.
2. **Choisis les 2 composants les plus sensibles** et justifie (indice : donnée d'enfant + point d'entrée acceptant des fichiers).
3. **Applique STRIDE** (section 2) à ces 2 composants : pour chaque lettre, écris la menace concrète *ou* « n/a » avec la raison. Formule chaque menace de façon **défensive** (« risque que… » → à prévenir), jamais comme un mode opératoire.
4. **Évalue chaque risque** : impact (1-3) et probabilité (1-3). Criticité = impact × probabilité.
5. **Trie le registre** (section 3) par criticité décroissante. Pour chaque ligne : contre-mesure envisagée + le **module du cours** qui la traite (01-11).
6. **Remplis la section 4** : comment vérifier (ex. test « parent B → 404 sur enfant A »), et le déclencheur de mise à jour du modèle.
7. **Relis avec la triade CIA** : chaque risque touche-t-il C, I ou D ? Un axe est-il sous-traité ?

---

## Corrigé complet commenté

> Corrigé de référence. Le tien peut différer : ce qui compte, c'est la **couverture** (STRIDE complet, surface exhaustive) et une **priorisation défendable**.

```markdown
# Modèle de menace — TribuZen (v1)

> Document défensif. Objectif : identifier et prioriser les risques pour les corriger.
> Rejoué à chaque nouvelle fonctionnalité. Auteur : Sylvain. Date : 2026-07.

## 1. Sur quoi travaille-t-on ? (surface d'attaque)

### Points d'entrée réseau
- POST /api/auth/login            — authentification (cible brute-force)
- GET  /api/children/:id          — fiche enfant (donnée mineure sensible)
- POST /api/children/:id/photo    — upload de fichier (surface élargie)
- GET  /api/messages?familyId=    — messagerie (données perso entre parents)
- POST /api/agenda                — écriture d'événement

### Entrées de données
- Params d'URL (:id, ?familyId) — devinables/énumérables
- Corps JSON (login, agenda)     — validation requise
- En-têtes / cookies (session, token d'auth)
- Fichiers uploadés (photo)      — type MIME, taille, nom, contenu

### Dépendances
- Packages npm (chacun = code exécuté chez nous) — cf. module 09 supply chain

### Secrets & configuration
- .env : URL BDD, clé de signature de session/JWT, clés d'API tierces
- Rôle BDD applicatif (doit être à privilège minimal)

### Facteur humain
- Mots de passe parents faibles, phishing, accès dépôt/CI des développeurs

## 2. Qu'est-ce qui peut mal tourner ? (STRIDE)

### Composant A — GET /api/children/:id  (le plus sensible : donnée d'enfant)
| Lettre | Menace (à prévenir) | Propriété |
|---|---|---|
| S Spoofing        | Requête non authentifiée acceptée → lecture par un anonyme | Authentification |
| T Tampering       | n/a — endpoint en lecture seule | Intégrité |
| R Repudiation     | Aucun journal d'accès → abus indétectable et non prouvable | Traçabilité |
| I Info disclosure | SELECT * expose des champs internes ; stack trace en cas d'erreur | Confidentialité |
| D Denial of svc   | Absence de rate limiting → énumération massive des :id | Disponibilité |
| E Elevation/IDOR  | Un parent lit l'enfant d'une AUTRE famille en changeant :id | Autorisation |

### Composant B — POST /api/children/:id/photo  (point d'entrée fichier)
| Lettre | Menace (à prévenir) | Propriété |
|---|---|---|
| S Spoofing        | Upload sans authentification | Authentification |
| T Tampering       | Fichier écrasant celui d'un autre enfant (nom de chemin manipulé) | Intégrité |
| R Repudiation     | Pas de trace de qui a uploadé quoi | Traçabilité |
| I Info disclosure | URL de photo devinable → accès hors famille | Confidentialité |
| D Denial of svc   | Fichiers énormes / uploads en rafale saturent le stockage | Disponibilité |
| E Elevation       | Uploader la photo d'un enfant d'une autre famille | Autorisation |

## 3. Registre de risques priorisé
| # | Risque | Impact | Proba | Criticité | Contre-mesure | Module |
|---|--------|:---:|:---:|:---:|---------|:---:|
| 1 | IDOR : lecture enfant d'une autre famille | 3 | 3 | 9 | Contrôle d'accès par ressource (family_id), 404 si non autorisé | 04 |
| 2 | Endpoint sans authentification | 3 | 2 | 6 | Middleware requireAuth sur toutes les routes /api | 03 |
| 3 | SELECT * / sur-exposition de champs | 3 | 2 | 6 | Sélection explicite des champs + DTO de réponse | 00/04 |
| 4 | Upload : type/taille non validés | 2 | 3 | 6 | Validation MIME réelle + limite de taille côté serveur | 08 |
| 5 | Brute-force sur /login | 2 | 3 | 6 | Rate limiting + hachage lent + verrouillage progressif | 03/08 |
| 6 | Pas de journalisation des accès sensibles | 2 | 2 | 4 | Log qui/quoi/quand (sans secrets) | 00/11 |
| 7 | Stack trace exposée en prod | 2 | 2 | 4 | Handler d'erreurs central, message générique au client | 00 |
| 8 | Dépendance npm vulnérable | 3 | 1 | 3 | npm audit + lockfile + revue en CI | 09 |

## 4. A-t-on fait un travail suffisant ?
- Vérifications ciblées :
  - parent B → 404 sur un enfant de la famille A (risque #1)
  - requête anonyme → 401 sur /api/children/:id (risque #2)
  - upload de 100 Mo ou de type non-image → rejeté (risque #4)
- Rejeu du modèle : à chaque nouvelle route, nouveau champ exposé, ou nouvelle dépendance.
- Lecture CIA : C bien couverte (#1, #3, #7), I à renforcer côté upload (#4), D via rate limiting (#4, #5).
```

**Pourquoi ce corrigé est correct :**
- La surface d'attaque couvre les **5 familles** (réseau, entrées, dépendances, secrets, humain) — pas seulement les routes.
- STRIDE est passé **en entier** sur chaque composant, y compris les « n/a » justifiés (montre qu'on a réfléchi, pas oublié).
- La priorisation par **impact × probabilité** fait remonter l'IDOR (#1) en tête : c'est le risque classique n°1 des API, et il touche directement une donnée d'enfant.
- Chaque risque pointe vers le **module** qui apporte la contre-mesure → le modèle devient le fil conducteur du cours.
- Tout est formulé **défensivement** (« risque que… », « à prévenir »), sans mode opératoire d'attaque.

---

## Variante J+30 (fading)

**Même exercice, contraintes ajoutées, sans rouvrir ce corrigé ni le module :**

1. **En 30 minutes**, modélise une **nouvelle** fonctionnalité TribuZen : `POST /api/families/:id/invite` (inviter un second parent par e-mail avec un lien contenant un token).
2. Impose-toi de trouver **au moins un risque par lettre STRIDE** (pas de « n/a » de facilité).
3. Ajoute une colonne **« coût de la contre-mesure »** (faible/moyen/élevé) au registre, et propose l'ordre de traitement en tenant compte du couple criticité/coût.

**Critère de réussite :** le registre est trié de façon défendable, chaque risque a une contre-mesure et un module, et le lien d'invitation (token devinable ? expiration ? usage unique ?) est analysé.

---

## Application TribuZen

Dans le repo `smaurier/tribuzen`, le document vit ici :

```
tribuzen/
  docs/
    security/
      threat-model.md      ← ce lab
```

**Différences par rapport au lab :**
- Le document est **vivant** : chaque PR qui ajoute une route ou un champ sensible met à jour la surface d'attaque et le registre (revue obligatoire).
- Les contre-mesures deviennent des **issues** liées aux modules du cours (ex. « #1 IDOR → implémenter le contrôle family_id, cf. module 04 »).
- La section 4 alimentera plus tard de vrais tests (auth/autorisation) et l'audit défensif du **module 11**.

**Commit cible :**
```
docs(security): premier modèle de menace TribuZen — surface d'attaque + STRIDE + registre priorisé
```
