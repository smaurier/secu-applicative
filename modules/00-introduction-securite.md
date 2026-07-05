---
titre: Introduction à la sécurité applicative (posture défensive)
cours: 14-securite-applicative
notions: ["triade CIA (confidentialité, intégrité, disponibilité)", modèle de menace, "STRIDE (catégories de menaces)", defense in depth, surface d'attaque, security by design, moindre privilège, posture défensive]
outcomes:
  - sait évaluer une fonctionnalité sous l'angle de la triade CIA
  - sait dresser un modèle de menace simple avec les 4 questions et STRIDE
  - sait cartographier la surface d'attaque d'une application web
  - sait appliquer defense in depth et moindre privilège à une décision de conception
prerequis: []
next: 01-owasp-top10
libs: []
tribuzen: transversal — posture sécurité de tout TribuZen (données famille/enfants sensibles), point d'entrée du cours sécurité
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Introduction à la sécurité applicative (posture défensive)

> **Outcomes — tu sauras FAIRE :** évaluer une fonctionnalité via la triade CIA, dresser un modèle de menace simple (4 questions + STRIDE), cartographier une surface d'attaque, appliquer defense in depth et moindre privilège.
> **Difficulté :** :star::star:
>
> **Angle du cours :** **défensif**. On regarde les vulnérabilités pour les **comprendre et les corriger**, jamais pour attaquer un système tiers. Ce module pose le vocabulaire et la posture ; les 13 modules suivants déclinent chaque famille de risque (OWASP, injection, auth, crypto, headers, CORS, supply chain…).
>
> **Portée :** ce module reste au niveau **méthode et posture**. L'infra cloud (secrets managés, WAF) est déférée au **cours 12** ; l'architecture sécurisée au **cours 13, module 20** ; le détail HTTP (cache, headers de transport) au **cours 11**.

## 1. Cas concret d'abord

Tu rejoins l'équipe TribuZen. Le produit gère des **familles** : profils d'enfants (prénom, date de naissance, école, allergies, photos), agenda partagé, messages entre parents. Le PO te confie une première fonctionnalité anodine :

> « Ajoute un endpoint `GET /api/children/:id` pour afficher la fiche d'un enfant dans l'app. »

Un collègue propose ce code, « ça marche, on verra la sécu plus tard » :

```ts
// ⚠️ Version "ça marche" — à auditer AVANT d'aller plus loin
app.get('/api/children/:id', async (req, res) => {
  const child = await db.query('SELECT * FROM children WHERE id = $1', [req.params.id])
  res.json(child)
})
```

**Ce n'est pas « fini ».** Prends 3 minutes et liste ce qui peut mal tourner. Sans jargon, juste du bon sens :

1. **Qui appelle cet endpoint ?** Rien ne vérifie que l'appelant est connecté → n'importe qui sur Internet lit la fiche.
2. **A-t-il le droit de voir CET enfant ?** Un parent authentifié de la famille A pourrait lire l'enfant `:id` de la famille B en changeant le numéro dans l'URL.
3. **Que renvoie `SELECT *` ?** Toutes les colonnes, y compris celles qu'on n'affiche jamais (notes internes, identifiants techniques, allergies médicales exposées sans raison).
4. **Que se passe-t-il en cas d'erreur ?** Une exception non gérée peut renvoyer une stack trace qui révèle la structure de la base.

Ces quatre questions **sont** un modèle de menace, en version débutant. Le reste du module te donne le vocabulaire pour les poser **systématiquement**, sur chaque fonctionnalité, avant de coder — c'est ça, la posture défensive. On corrigera ce endpoint au fil des modules (authentification → 03, autorisation/IDOR → 04, moindre privilège → ici et 04).

---

## 2. Théorie complète, concise

### 2.1 La posture défensive : penser en « et si ? »

Un développeur pense au **chemin heureux** : l'utilisateur fait ce qui est prévu. Un défenseur ajoute une seconde lecture : **« et si l'appelant est hostile, distrait, ou usurpé ? »** La sécurité applicative n'est pas une couche qu'on ajoute à la fin — c'est une **question qu'on se pose à chaque décision** : chaque entrée est-elle validée ? chaque accès est-il autorisé ? chaque erreur est-elle discrète ?

> **Cadrage éthique :** tout ce cours est **défensif**. On étudie une attaque pour savoir la **détecter et la bloquer** sur *nos propres* systèmes. Tester un système sans autorisation écrite est illégal (voir module 11, divulgation responsable).

### 2.2 La triade CIA — la grille d'évaluation universelle

Toute décision de sécurité s'évalue sous trois propriétés (source : MDN Web Security ; c'est le socle du domaine).

| Propriété | Question | Exemple TribuZen | Menace si violée |
|---|---|---|---|
| **Confidentialité** | *Qui peut lire ?* | Les allergies d'un enfant ne sont lisibles que par sa famille | Fuite de données |
| **Intégrité** | *Qui peut modifier, et est-ce détectable ?* | Un parent ne peut pas altérer l'agenda d'une autre famille | Falsification silencieuse |
| **Disponibilité** | *Le service répond-il quand on en a besoin ?* | L'app reste joignable même sous charge | Déni de service |

Les trois sont en **tension** : chiffrer parfaitement (confidentialité) mais tomber en panne sans cesse viole la disponibilité. Une bonne conception équilibre les trois selon la sensibilité des données. Pour des **données d'enfants**, la confidentialité et l'intégrité priment.

### 2.3 Le modèle de menace — les 4 questions

Le *threat modeling* (modélisation des menaces) répond à quatre questions de cadrage (source : Threat Modeling Manifesto, via OWASP Threat Modeling Cheat Sheet) :

1. **Sur quoi travaille-t-on ?** — décrire le système, les données, les flux (un diagramme suffit).
2. **Qu'est-ce qui peut mal tourner ?** — lister les menaces (STRIDE aide ici, §2.4).
3. **Qu'est-ce qu'on fait à ce sujet ?** — définir les contre-mesures (les protections des modules suivants).
4. **A-t-on fait un travail suffisant ?** — vérifier, tester, réévaluer.

C'est un cycle, pas un document mort : on le rejoue à chaque évolution du produit.

### 2.4 STRIDE — six familles de menaces

STRIDE (Microsoft, popularisé par OWASP) structure la question « qu'est-ce qui peut mal tourner ? ». Chaque lettre = une menace qui viole **une** propriété de sécurité (source : OWASP Threat Modeling Cheat Sheet).

| Lettre | Menace | Propriété violée | Exemple (défensif — à prévenir) |
|---|---|---|---|
| **S** | Spoofing (usurpation) | Authentification | Se faire passer pour un parent via un token volé |
| **T** | Tampering (falsification) | Intégrité | Modifier une donnée sans autorisation |
| **R** | Repudiation (répudiation) | Traçabilité (*accounting*) | Nier une action faute de journal fiable |
| **I** | Information Disclosure (fuite) | Confidentialité | Stack trace exposée en production |
| **D** | Denial of Service (déni) | Disponibilité | Endpoint sans limite de débit saturé |
| **E** | Elevation of Privilege (élévation) | Autorisation | Un parent accède au panneau admin |

Passer chaque composant au crible des six lettres transforme « je ne sais pas ce qui peut arriver » en une checklist finie et actionnable.

### 2.5 Surface d'attaque — tout ce qui est exposé

La **surface d'attaque** est l'ensemble des points par lesquels un attaquant peut interagir avec le système. La réduire est la première protection : *ce qui n'existe pas ne peut pas être attaqué*.

Pour une app web TribuZen, la surface inclut :

- **Points d'entrée réseau** : chaque route d'API (`/api/children`, `/api/messages`…), le formulaire de login, l'upload de photos.
- **Entrées de données** : params d'URL, corps JSON, en-têtes, cookies, fichiers uploadés, webhooks tiers.
- **Dépendances** : chaque package npm est du code exécuté chez toi (module 09, supply chain).
- **Secrets & config** : variables d'environnement, clés d'API, connexions BDD.
- **Humains** : phishing, mots de passe faibles, accès développeur.

Réduire la surface = supprimer les endpoints inutilisés, ne demander que les données nécessaires, verrouiller les valeurs par défaut, retirer les dépendances mortes.

### 2.6 Defense in depth — plusieurs couches

Aucune protection n'est infaillible. La **défense en profondeur** superpose des couches indépendantes : si l'une cède, la suivante tient (source : MDN — « no single defense is sufficient »).

```
Requête entrante
   │
   ├─ Transport      → HTTPS / TLS (chiffrement en transit)
   ├─ Bordure        → rate limiting, en-têtes de sécurité (CSP, HSTS…)  → modules 06-08
   ├─ Application     → validation des entrées, authentification, autorisation → modules 02-04
   ├─ Données         → moindre privilège BDD, chiffrement au repos → modules 04-05
   └─ Observabilité   → journalisation, alerting (transversal)
```

Notre endpoint du §1 échoue sur **plusieurs** couches à la fois (pas d'auth, pas d'autorisation, `SELECT *`) — d'où l'intérêt de raisonner par couches plutôt que par correctif ponctuel.

### 2.7 Moindre privilège & security by design

- **Moindre privilège** : chaque acteur (utilisateur, service, requête SQL, conteneur) reçoit *le minimum* de droits pour sa tâche. Le `SELECT *` du §1 le viole : l'endpoint lit des colonnes qu'il n'affiche pas. La version correcte ne sélectionne que les champs affichés.
- **Security by design** : la sécurité est intégrée **dès la conception**, pas auditée à la fin. Corriger une faille en conception coûte une fraction de son coût en production. Concrètement : un modèle de menace au moment de spécifier la fonctionnalité, pas après le déploiement.

Ces deux principes sont des **réflexes**, pas des outils : ils s'appliquent à chaque ligne de décision.

---

## 3. Worked examples

### Exemple 1 — Modèle de menace de l'endpoint `GET /api/children/:id`

On applique les 4 questions + STRIDE au code du §1.

**Q1 — Sur quoi travaille-t-on ?**
Flux : `Client → API → BDD`. Donnée : fiche enfant (sensible : mineur). Acteurs : parent légitime, parent d'une autre famille, visiteur anonyme.

**Q2 — Qu'est-ce qui peut mal tourner ? (STRIDE)**

| Lettre | Menace concrète sur cet endpoint |
|---|---|
| S (spoofing) | Aucune authentification → n'importe qui appelle l'endpoint |
| T (tampering) | Hors périmètre ici (endpoint en lecture) |
| R (repudiation) | Aucun journal d'accès → impossible de savoir qui a lu quoi |
| I (info disclosure) | `SELECT *` renvoie trop de colonnes ; erreurs non gérées → stack trace |
| D (denial of service) | Pas de rate limiting → énumération massive des `:id` |
| E (elevation) | Un parent lit l'enfant d'une autre famille en changeant `:id` (IDOR) |

**Q3 — Qu'est-ce qu'on fait ?** (contre-mesures, détaillées dans les modules cités)

```ts
// Version durcie — commentée couche par couche
app.get(
  '/api/children/:id',
  rateLimiter,            // D : limite le débit (module 08)
  requireAuth,            // S : refuse les requêtes non authentifiées (module 03)
  async (req, res, next) => {
    try {
      const child = await db.query(
        // I + moindre privilège : uniquement les champs affichés, pas SELECT *
        'SELECT id, first_name, birth_date, avatar_url FROM children WHERE id = $1',
        [req.params.id],
      )
      if (!child) return res.status(404).end()          // pas de fuite d'existence

      // E (IDOR) : l'enfant doit appartenir à la famille de l'appelant (module 04)
      if (child.family_id !== req.user.familyId) {
        return res.status(404).end()                     // 404, pas 403 : ne révèle pas l'existence
      }

      logger.info({ userId: req.user.id, childId: child.id, action: 'read' }) // R : trace
      res.json(child)
    } catch (err) {
      next(err)            // I : gestion centralisée, pas de stack trace au client
    }
  },
)
```

**Q4 — A-t-on fait un travail suffisant ?** Test : un parent de la famille B reçoit bien `404` sur un enfant de la famille A ; un anonyme reçoit `401`. On rejouera ce modèle à chaque nouveau champ exposé.

### Exemple 2 — Évaluer une fonctionnalité via CIA + surface d'attaque

Nouvelle demande : « permettre l'upload de la photo de profil d'un enfant ».

| Angle | Analyse |
|---|---|
| **Confidentialité** | La photo est une donnée d'enfant → accès restreint à la famille ; URL non devinable |
| **Intégrité** | Vérifier le type de fichier réel (pas seulement l'extension) ; empêcher l'écrasement d'un autre fichier |
| **Disponibilité** | Limiter la taille et la fréquence des uploads (éviter la saturation du stockage) |
| **Surface d'attaque ajoutée** | Nouveau point d'entrée acceptant des **fichiers** : risque de contenu malveillant, de faux type MIME, de chemin de stockage manipulé |

Conclusion défensive : valider le type et la taille côté serveur, stocker hors de la racine web, générer un nom de fichier non devinable, servir via une URL contrôlée. La décision de sécurité est prise **avant** d'écrire le handler — security by design.

---

## 4. Pièges & misconceptions

### PIÈGE #1 — « La sécurité, c'est pour la fin du projet »

Faux. Corriger en production coûte bien plus cher qu'en conception, et certaines failles (mauvais modèle d'autorisation) imposent une refonte. **Correct :** un mini modèle de menace *pendant* la spec de chaque fonctionnalité (security by design).

### PIÈGE #2 — Confondre authentification et autorisation

- **Authentification** = *qui es-tu ?* (prouver son identité).
- **Autorisation** = *as-tu le droit de faire ça ?* (sur cette ressource précise).

Un parent authentifié qui lit l'enfant d'une autre famille est **authentifié mais non autorisé** (faille IDOR/BOLA, module 04). Vérifier l'un ne dispense jamais de l'autre.

### PIÈGE #3 — « On est en HTTPS, donc c'est sécurisé »

HTTPS protège les données **en transit** (confidentialité/intégrité sur le réseau). Il ne dit rien sur qui appelle, ce qu'il a le droit de faire, ni sur la validation des entrées. C'est **une** couche de defense in depth, pas la sécurité entière.

### PIÈGE #4 — « L'obscurité protège » (security through obscurity)

Cacher une URL ou renommer un paramètre n'est **pas** une protection : un attaquant les découvre. L'obscurité peut *compléter* une vraie mesure (ex. IDs non devinables *en plus* d'un contrôle d'accès), jamais la remplacer.

### PIÈGE #5 — Répudiation oubliée : pas de journal = pas de preuve

Sans journalisation des accès sensibles, on ne peut ni détecter un abus, ni prouver qui a fait quoi (le **R** de STRIDE). Beaucoup d'équipes protègent l'accès mais oublient de le **tracer**. Journaliser *qui*, *quoi*, *quand* — sans jamais logguer de secret (mot de passe, token) dans le message.

### PIÈGE #6 — `SELECT *` et sur-exposition de données

Renvoyer toutes les colonnes viole le moindre privilège et la confidentialité : on expose des champs internes « par accident ». **Correct :** sélectionner explicitement les champs affichés, côté requête ET côté sérialisation de la réponse.

---

## 5. Ancrage TribuZen

Ce module fixe la **posture de sécurité transversale** de TribuZen. L'enjeu est réel : le produit manipule des **données d'enfants mineurs** (identité, école, santé/allergies, photos), catégorie particulièrement sensible au regard du RGPD. Une fuite n'est pas un incident technique abstrait — c'est l'exposition d'enfants.

Concrètement, tout au long du cours, on applique à `smaurier/tribuzen` :

- **Un modèle de menace par domaine** : `children`, `messages`, `agenda`, `auth`. Chaque nouveau endpoint passe les 4 questions + STRIDE avant merge.
- **CIA comme grille de revue** : chaque PR touchant à une donnée famille répond « qui peut lire / modifier / est-ce disponible ? ».
- **Defense in depth** : TLS (transport) → en-têtes + rate limiting (bordure) → auth + autorisation + validation (app) → moindre privilège BDD (données) → journalisation (observabilité).
- **Moindre privilège** partout : rôles BDD dédiés (pas de superuser applicatif), requêtes à champs explicites, tokens à portée minimale.

Artefact concret de ce module (voir lab) : un fichier `docs/security/threat-model.md` dans le repo TribuZen, qui recense la surface d'attaque et les risques priorisés. Il devient la référence vivante mise à jour à chaque fonctionnalité.

> Les mécanismes cités (auth, autorisation, en-têtes, CORS, crypto, supply chain) sont **détaillés dans les modules 01 à 11**. Ici, on installe le réflexe et le vocabulaire.

---

## 6. Points clés

1. **Posture défensive** = se demander « et si l'appelant est hostile ? » à chaque décision, dès la conception.
2. **Triade CIA** : Confidentialité (qui lit ?), Intégrité (qui modifie ?), Disponibilité (ça répond ?) — la grille d'évaluation de toute mesure.
3. **Modèle de menace = 4 questions** : sur quoi ? qu'est-ce qui peut mal tourner ? qu'est-ce qu'on fait ? est-ce suffisant ?
4. **STRIDE** : Spoofing/Tampering/Repudiation/Info disclosure/DoS/Elevation — une checklist finie des « qu'est-ce qui peut mal tourner ».
5. **Surface d'attaque** = tout ce qui est exposé ; la réduire est la première protection (ce qui n'existe pas ne s'attaque pas).
6. **Defense in depth** : plusieurs couches indépendantes ; aucune n'est infaillible seule.
7. **Moindre privilège & security by design** : droits minimaux, sécurité intégrée dès la spec — des réflexes, pas des outils.
8. Ne pas confondre **authentification** (qui es-tu ?) et **autorisation** (as-tu le droit ?).

---

## 7. Seeds Anki

```
Que signifie la triade CIA en sécurité ?|Confidentialité (qui peut lire), Intégrité (qui peut modifier et est-ce détectable), Disponibilité (le service répond quand nécessaire). Grille d'évaluation de toute mesure de sécurité.
Quelles sont les 4 questions d'un modèle de menace ?|1) Sur quoi travaille-t-on ? 2) Qu'est-ce qui peut mal tourner ? 3) Qu'est-ce qu'on fait ? 4) A-t-on fait un travail suffisant ? (Threat Modeling Manifesto / OWASP)
Que couvre l'acronyme STRIDE et à quoi sert-il ?|Spoofing (authentification), Tampering (intégrité), Repudiation (traçabilité), Information disclosure (confidentialité), Denial of service (disponibilité), Elevation of privilege (autorisation). Structure la question "qu'est-ce qui peut mal tourner".
Quelle est la différence entre authentification et autorisation ?|Authentification = prouver QUI tu es. Autorisation = as-tu le DROIT de faire cette action sur cette ressource. Un utilisateur peut être authentifié mais non autorisé (ex. IDOR).
Qu'est-ce que la surface d'attaque et pourquoi la réduire ?|L'ensemble des points par lesquels un attaquant peut interagir (routes, entrées, dépendances, secrets, humains). La réduire est la 1re protection : ce qui n'existe pas ne peut pas être attaqué.
Qu'est-ce que la defense in depth ?|Superposer plusieurs couches de protection indépendantes (transport, bordure, application, données, observabilité). Si une couche cède, la suivante tient — aucune n'est infaillible seule.
Pourquoi "on est en HTTPS donc c'est sécurisé" est-il un piège ?|HTTPS protège les données en transit uniquement. Il ne dit rien sur l'authentification, l'autorisation ni la validation des entrées. C'est UNE couche de defense in depth, pas la sécurité entière.
Pourquoi SELECT * dans une API viole-t-il le moindre privilège ?|Il renvoie toutes les colonnes, y compris des champs internes/sensibles jamais affichés → sur-exposition de données. Correct : sélectionner explicitement les champs affichés.
```

---

## Pont vers le lab

> Lab associé : `labs/lab-00-introduction-securite/README.md`. Exercice **défensif** : dresser le modèle de menace et la surface d'attaque de TribuZen, puis prioriser les risques — aucun outil offensif, on produit un document de référence.
