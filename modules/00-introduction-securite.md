# Module 0 — Introduction à la Sécurité Applicative

## Objectifs pédagogiques

- Comprendre pourquoi la sécurité est un enjeu critique du développement logiciel
- Maîtriser les concepts fondamentaux (CIA, defense in depth, moindre privilège)
- Connaître les méthodologies de threat modeling
- Intégrer la sécurité dans le cycle de développement (SDLC)
- Identifier les outils essentiels du développeur sécurité

---

## 1. Pourquoi la sécurité est importante

### Le coût des failles

Les failles de sécurité ont un impact direct sur les organisations :

- **Coût moyen d'une data breach** : 4,45 millions de dollars en 2023 (IBM Cost of a Data Breach Report)
- **Temps moyen de détection** : 204 jours pour identifier une brèche
- **Temps moyen de correction** : 73 jours supplémentaires pour la contenir
- **Impact réputationnel** : perte de confiance clients, chute boursière, amendes RGPD (jusqu'à 4% du CA mondial)

### Exemples marquants

| Incident | Année | Impact |
|---|---|---|
| Equifax | 2017 | 147 millions de personnes touchées, amende de 700M$ |
| Capital One | 2019 | 100 millions de dossiers exposés via SSRF |
| Log4Shell | 2021 | Vulnérabilité critique dans une librairie omniprésente |
| MOVEit | 2023 | Supply chain attack affectant des centaines d'organisations |

### Le coût de la correction

Plus une faille est découverte tard, plus elle coûte cher à corriger :

```
Phase de conception     → coût x1
Phase de développement  → coût x6
Phase de test           → coût x15
En production           → coût x100
```

> **Règle d'or** : intégrer la sécurité dès la conception est bien moins coûteux que de corriger après coup.

---

## 2. Le Triangle CIA

Les trois piliers fondamentaux de la sécurité de l'information :

### Confidentialité (Confidentiality)

S'assurer que l'information n'est accessible qu'aux personnes autorisées.

- Chiffrement des données au repos et en transit
- Contrôle d'accès strict
- Classification des données

### Intégrité (Integrity)

Garantir que les données n'ont pas été modifiées de manière non autorisée.

- Signatures numériques et HMAC
- Checksums et hash de vérification
- Journalisation des modifications (audit trail)

### Disponibilité (Availability)

Assurer que les systèmes et données sont accessibles quand nécessaire.

- Redondance et haute disponibilité
- Protection contre les attaques DDoS
- Plans de reprise d'activité (PRA)

```
         Confidentialité
              /\
             /  \
            /    \
           / CIA  \
          /________\
   Intégrité      Disponibilité
```

> Chaque décision de sécurité doit être évaluée sous l'angle de ces trois piliers. Un système qui chiffre parfaitement les données mais tombe en panne constamment ne respecte pas la disponibilité.

---

## 3. Threat Modeling avec STRIDE

Le **threat modeling** est le processus d'identification des menaces potentielles pesant sur un système. Le modèle **STRIDE**, développé par Microsoft, catégorise les menaces :

| Lettre | Menace | Propriété violée | Exemple |
|---|---|---|---|
| **S** | Spoofing (usurpation d'identité) | Authentification | Se connecter avec les credentials d'un autre utilisateur |
| **T** | Tampering (falsification) | Intégrité | Modifier un JWT sans re-signer |
| **R** | Repudiation (répudiation) | Non-répudiation | Nier avoir effectué une transaction |
| **I** | Information Disclosure (fuite d'info) | Confidentialité | Stack trace exposée en production |
| **D** | Denial of Service (déni de service) | Disponibilité | Bombarder un endpoint non protégé par rate limiting |
| **E** | Elevation of Privilege (élévation de privilèges) | Autorisation | Un utilisateur lambda accède au panel admin |

### Processus de Threat Modeling

1. **Décomposer** l'application (diagramme de flux de données)
2. **Identifier** les menaces avec STRIDE pour chaque composant
3. **Évaluer** les risques (probabilité × impact)
4. **Définir** les contre-mesures
5. **Valider** que les contre-mesures sont efficaces

---

## 4. Defense in Depth (sécurité en couches)

Le principe de **défense en profondeur** consiste à superposer plusieurs couches de sécurité. Si une couche est compromise, les suivantes protègent toujours le système.

```
┌──────────────────────────────────┐
│         Couche réseau            │  → Firewall, WAF, DDoS protection
│  ┌────────────────────────────┐  │
│  │     Couche application     │  │  → Validation input, CSP, CORS
│  │  ┌──────────────────────┐  │  │
│  │  │   Couche données     │  │  │  → Chiffrement, contrôle d'accès BD
│  │  │  ┌────────────────┐  │  │  │
│  │  │  │  Données        │  │  │  │  → Classification, backup
│  │  │  └────────────────┘  │  │  │
│  │  └──────────────────────┘  │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

### Application concrète en développement web

```typescript
// Couche 1 : Rate limiting (réseau/middleware)
import rateLimit from 'express-rate-limit';
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter);

// Couche 2 : Validation des entrées (application)
import { z } from 'zod';
const UserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(12).max(128),
});

// Couche 3 : Authentification (application)
app.use('/api/protected', authenticateJWT);

// Couche 4 : Autorisation (application)
app.use('/api/admin', requireRole('admin'));

// Couche 5 : Chiffrement des données (données)
// bcrypt pour les mots de passe, AES pour les données sensibles

// Couche 6 : Logging et monitoring (transversal)
app.use(securityLogger);
```

---

## 5. Principe du moindre privilège

> Un utilisateur, un processus ou un programme ne doit avoir que les permissions minimales nécessaires pour accomplir sa tâche.

### Exemples d'application

```typescript
// ❌ Mauvais : un endpoint qui expose toutes les données utilisateur
app.get('/api/users/:id', async (req, res) => {
  const user = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
  res.json(user); // Expose le hash du mot de passe, l'email, etc.
});

// ✅ Bon : ne retourner que les champs nécessaires
app.get('/api/users/:id', async (req, res) => {
  const user = await db.query(
    'SELECT id, display_name, avatar_url FROM users WHERE id = $1',
    [req.params.id]
  );
  res.json(user);
});
```

### En base de données

```sql
-- ❌ Mauvais : l'application utilise le superuser
-- ✅ Bon : créer un utilisateur dédié avec permissions minimales
CREATE ROLE app_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_readonly;

CREATE ROLE app_readwrite;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO app_readwrite;
-- Pas de DELETE, pas de DROP, pas de TRUNCATE
```

### En infrastructure

- Conteneurs Docker : ne pas exécuter en `root`
- AWS IAM : politiques spécifiques par service, pas de `AdministratorAccess`
- Variables d'environnement : chaque service n'a accès qu'à ses propres secrets

---

## 6. Security by Design vs Security as Afterthought

### Security as Afterthought (à éviter)

1. On développe l'application
2. On fait un audit de sécurité à la fin
3. On découvre des dizaines de failles
4. On patche dans la panique avant le release

### Security by Design (recommandé)

La sécurité est intégrée à chaque étape :

| Phase | Actions sécurité |
|---|---|
| **Exigences** | Identifier les exigences de sécurité, classification des données |
| **Conception** | Threat modeling, choix d'architecture sécurisée |
| **Implémentation** | Revue de code, utilisation de librairies éprouvées, SAST |
| **Test** | Tests de sécurité automatisés, pen testing, DAST |
| **Déploiement** | Hardening, configuration sécurisée, secrets management |
| **Maintenance** | Monitoring, patch management, réponse aux incidents |

---

## 7. Les différents types d'attaquants

### Script Kiddies

- Utilisent des outils et scripts existants sans comprendre leur fonctionnement
- Motivation : curiosité, défi, vandalisme
- Niveau technique : faible
- Ciblent les failles connues et non patchées

### Hacktivistes

- Motivés par des causes politiques ou sociales
- Attaques DDoS, defacement, fuites de données
- Exemples : Anonymous, LulzSec

### Cybercriminels organisés

- Motivation financière (ransomware, vol de données, fraude)
- Ressources significatives et méthodes sophistiquées
- Économie souterraine (vente de données, RaaS - Ransomware as a Service)

### APT (Advanced Persistent Threats)

- Acteurs étatiques ou groupes sponsorisés par des États
- Attaques ciblées, persistantes, très sophistiquées
- Objectifs : espionnage, sabotage, influence
- Exemples : APT29 (Cozy Bear), APT28 (Fancy Bear)

### Insiders (menaces internes)

- Employés malveillants ou négligents
- Accès légitime aux systèmes
- Difficiles à détecter
- Responsables de 25% des data breaches

---

## 8. Cycle de développement sécurisé (Secure SDLC)

### Approche DevSecOps

Intégrer la sécurité dans le pipeline CI/CD :

```
Code → Build → Test → Deploy → Monitor
  ↓      ↓       ↓       ↓        ↓
SAST   SCA    DAST   Config    SIEM
Lint   SBOM   Pen    Scan     Alerting
```

### Étapes clés

1. **Pre-commit hooks** : linters de sécurité, détection de secrets
2. **CI pipeline** : SAST, SCA, tests de sécurité automatisés
3. **Staging** : DAST, pen testing
4. **Production** : WAF, monitoring, alerting
5. **Post-incident** : forensics, post-mortem, amélioration continue

```typescript
// Exemple de pre-commit hook avec Husky
// .husky/pre-commit
// npx secretlint "**/*"
// npx eslint --rule 'security/*' src/
```

---

## 9. Outils essentiels du développeur sécurité

### SAST (Static Application Security Testing)

Analyse du code source sans l'exécuter.

| Outil | Langage | Description |
|---|---|---|
| **ESLint + eslint-plugin-security** | JS/TS | Règles de sécurité pour JavaScript |
| **Semgrep** | Multi | Analyse statique configurable avec règles communautaires |
| **SonarQube** | Multi | Plateforme complète de qualité et sécurité du code |
| **CodeQL** | Multi | Analyse sémantique du code (GitHub) |

### DAST (Dynamic Application Security Testing)

Teste l'application en cours d'exécution.

| Outil | Description |
|---|---|
| **OWASP ZAP** | Scanner de vulnérabilités web open-source |
| **Burp Suite** | Outil professionnel de test de sécurité web |
| **Nuclei** | Scanner rapide basé sur des templates |

### SCA (Software Composition Analysis)

Analyse des dépendances pour les vulnérabilités connues.

| Outil | Description |
|---|---|
| **npm audit** | Intégré à npm, vérifie les CVE des dépendances |
| **Snyk** | Analyse de vulnérabilités et fix automatique |
| **Dependabot** | Mise à jour automatique des dépendances (GitHub) |
| **Socket.dev** | Détection de supply chain attacks |

### Détection de secrets

| Outil | Description |
|---|---|
| **git-secrets** | Pre-commit hook pour détecter les secrets |
| **truffleHog** | Scan l'historique git pour les secrets exposés |
| **secretlint** | Linter configurable pour la détection de secrets |

### Mise en pratique

```bash
# Installer les outils de base pour un projet Node.js
npm install --save-dev eslint-plugin-security
npx secretlint --init

# Lancer un audit des dépendances
npm audit

# Scanner avec Semgrep
semgrep --config auto src/

# Scanner avec OWASP ZAP (mode API)
zap-cli quick-scan http://localhost:3000
```

---

## 10. Résumé

| Concept | Points clés |
|---|---|
| **CIA** | Confidentialité, Intégrité, Disponibilité — les 3 piliers |
| **STRIDE** | 6 catégories de menaces pour le threat modeling |
| **Defense in Depth** | Plusieurs couches de sécurité superposées |
| **Moindre privilège** | Permissions minimales nécessaires uniquement |
| **Security by Design** | Intégrer la sécurité dès la conception |
| **Secure SDLC** | Sécurité à chaque phase du cycle de développement |
| **SAST/DAST/SCA** | Les trois familles d'outils d'analyse de sécurité |

---

## Pour aller plus loin

- [OWASP — Open Web Application Security Project](https://owasp.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CWE — Common Weakness Enumeration](https://cwe.mitre.org/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- Livre : *The Web Application Hacker's Handbook* — Dafydd Stuttard, Marcus Pinto
