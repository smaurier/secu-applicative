---
titre: Sécurité de la supply chain — dépendances, audit, lockfile, provenance
cours: 14-securite-applicative
notions: ["supply chain / chaîne d'approvisionnement logicielle", "dépendances directes vs transitives", "npm audit (bulk advisory)", "niveaux CVSS / sévérité", "lockfile (package-lock.json)", "npm ci vs npm install", "integrity SHA-512 (SRI)", "pinning / version ranges semver", "typosquatting", "dependency confusion (substitution)", "lifecycle scripts (preinstall / postinstall)", "SBOM (SPDX / CycloneDX)", "provenance & signatures (Sigstore)", "vérification en CI"]
outcomes:
  - "sait auditer les dépendances d'un projet npm (npm audit, lecture d'un rapport, niveaux de sévérité) et remédier sans casser la prod"
  - "sait expliquer le rôle du lockfile (versions exactes + integrity SHA-512) et pourquoi la CI doit utiliser npm ci et non npm install"
  - "sait reconnaître et prévenir le typosquatting et la dependency confusion (scopes, registre unique, claim de scope)"
  - "sait neutraliser les scripts d'installation malveillants (lifecycle scripts) et inspecter un paquet avant de l'installer"
  - "sait générer un SBOM, comprendre la provenance/signatures npm, et brancher une porte de sécurité supply chain en CI"
prerequis:
  - "Introduction sécurité — modèle de menace, defense in depth (module 00)"
  - "OWASP Top 10 2021 — A06 Vulnerable and Outdated Components, A08 Software and Data Integrity Failures (module 01)"
  - "API security — validation, CI, chaîne de build (module 08)"
next: 10-infrastructure-securite
libs: []
tribuzen: chaîne de build TribuZen — dépendances npm du front, du back-office et de la CI (audit, lockfile, provenance)
last-reviewed: 2026-07
---

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

# Sécurité de la supply chain — dépendances, audit, lockfile, provenance

> **Outcomes — tu sauras FAIRE :** auditer et remédier les dépendances d'un projet npm, verrouiller les installs avec le lockfile et `npm ci`, prévenir typosquatting et dependency confusion, neutraliser les scripts d'install malveillants, et brancher une porte de sécurité supply chain en CI (audit, SBOM, provenance).
> **Difficulté :** :star::star::star:
>
> **Angle : DÉFENSIF.** On étudie les attaques supply chain pour **détecter et durcir TA propre chaîne de build**, jamais pour publier un paquet malveillant ou attaquer un registre tiers.
>
> **Portée :** ce module couvre le **code que tu ne contrôles pas** — tes dépendances et ta chaîne d'install/build. La gestion des **secrets et le durcissement de l'infra** (registre privé auto-hébergé, TLS) est le **module 10**. La sécurité **du code que tu écris** (injection, auth, headers) est couverte aux modules 02–08.

## 1. Cas concret d'abord

Tu ouvres le back-office TribuZen — celui qui manipule des **données de mineurs**. Un `npm install` récent a mis à jour le lockfile, et un collègue a ajouté un paquet la veille. Voici l'état du `package.json` et un extrait de l'install.

```jsonc
// package.json — AVANT durcissement
{
  "name": "tribuzen-api",
  "dependencies": {
    "express": "^4.18.0",          // (1) range large : ^ accepte tout 4.x à venir
    "cross-env": "*",              // (2) "*" : littéralement n'importe quelle version
    "colors": "1.4.44-liberty2",   // (3) version bizarre d'un paquet ultra-connu ?
    "@tribuzen/ui-kit": "^2.1.0"   // (4) paquet interne... résolu depuis quel registre ?
  },
  "scripts": {
    "postinstall": "node scripts/setup.js"
  }
}
```

```bash
$ npm install
...
> react-helper@1.0.0 postinstall     # (5) tu n'as jamais ajouté "react-helper"
> node -e "require('child_process').exec('curl https://…')"
```

**Cinq trous que ce module va boucher :**

1. **Ranges trop larges** (`^4.18.0`) — un prochain `npm install` peut tirer une version publiée *après* ta revue, sans que tu la relises.
2. **`"*"`** — aucune borne : une version compromise majeure est acceptée automatiquement.
3. **Typosquatting / paquet détourné** — `colors` a été saboté en 2022 ; une version au nom exotique est un signal d'alarme.
4. **Dependency confusion** — `@tribuzen/ui-kit` est *interne* ; si npm interroge aussi le registre public, un attaquant qui y publie `@tribuzen/ui-kit@99.0.0` gagne.
5. **Script `postinstall` malveillant** — un paquet transitif exécute du code **automatiquement** pendant l'install, avant même que tu lances l'app.

À la fin du module, ce projet a un lockfile vérifié en CI avec `npm ci`, `npm audit` en porte bloquante, des dépendances internes protégées par scope + registre unique, les lifecycle scripts sous contrôle, et un SBOM généré. C'est le fil rouge du lab.

---

## 2. Théorie complète, concise

### 2.1 Ce qu'est une attaque supply chain

Plutôt que d'attaquer ton code, l'adversaire compromet **une brique que tu importes**. Une app npm moyenne tire des **centaines** de paquets *transitifs* (les dépendances de tes dépendances) : chacun s'exécute avec les mêmes droits que ton app. C'est **A06 (Vulnerable and Outdated Components)** et **A08 (Software and Data Integrity Failures)** de l'OWASP Top 10 2021.

- **Dépendance directe** — listée dans *ton* `package.json`.
- **Dépendance transitive** — tirée par une de tes dépendances. Tu ne l'as jamais choisie, mais elle tourne chez toi.

Cas réels à connaître (culture de menace, pas mode d'emploi) : **event-stream** (2018, dépendance transitive piégée visant des wallets), **ua-parser-js** (2021, compte mainteneur compromis → cryptominer), **colors.js / faker.js** (2022, sabotage volontaire du mainteneur → boucle infinie), **node-ipc** (2022, code destructeur géolocalisé). Le point commun : **le code venait d'un paquet de confiance**.

### 2.2 Auditer : `npm audit`

`npm audit` envoie la liste de tes dépendances (via le *Bulk Advisory endpoint* du registre) et récupère un rapport de vulnérabilités connues. Il **sort avec le code 0 si aucune vulnérabilité** n'est trouvée — c'est ce qui le rend utilisable en CI.

```bash
npm audit                       # rapport complet
npm audit --audit-level=high    # n'échoue (exit ≠ 0) qu'à partir de "high"
npm audit fix                   # applique les correctifs compatibles (lance un npm install)
npm audit fix --force           # ⚠️ autorise les sauts semver-MAJOR → breaking changes probables
```

Valeurs de `--audit-level` : `info`, `low`, `moderate`, `high`, `critical`, `none`. Elles fixent la **sévérité minimale qui fait échouer** la commande.

Sévérité (échelle CVSS) :

| Niveau | Score CVSS | Réaction typique |
|---|---|---|
| **Critical** | 9.0–10.0 | corriger immédiatement |
| **High** | 7.0–8.9 | corriger sous 24–48 h |
| **Moderate** | 4.0–6.9 | corriger dans la semaine |
| **Low** | 0.1–3.9 | planifier |

> `npm audit` ne voit que les **CVE déjà publiées**. Un paquet malveillant *frais* (typosquat, sabotage récent) n'y figure pas encore : l'audit est nécessaire, pas suffisant.

### 2.3 Le lockfile : versions exactes + intégrité

`package.json` déclare des **intentions** (`^4.18.0` = « n'importe quel 4.x »). `package-lock.json` fige la **réalité résolue** pour que « tes coéquipiers, tes déploiements et la CI installent exactement les mêmes dépendances ». Deux champs clés par paquet :

- **`resolved`** — l'URL/emplacement **exact** d'où le paquet a été tiré (registre, tarball, git SHA).
- **`integrity`** — un hash **SHA-512** au format Subresource Integrity (SRI). Si le contenu du paquet diffère du hash attendu, l'install **échoue**.

```jsonc
// extrait de package-lock.json (lockfileVersion 3, npm 9+)
"node_modules/express": {
  "version": "4.18.2",
  "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
  "integrity": "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ=="
}
```

**Le lockfile doit être commité.** Sans lui, deux `npm install` à deux dates peuvent produire des arbres de dépendances différents (« works on my machine »), et une version fraîchement compromise peut entrer sans revue.

### 2.4 `npm ci` vs `npm install` (la règle CI)

| Commande | Comportement |
|---|---|
| `npm install` | résout les ranges, **peut modifier** le lockfile et `node_modules` |
| `npm ci` | installe **exactement** le lockfile, **ignore les ranges** de `package.json`, échoue si les deux divergent |

`npm ci` supprime `node_modules` et réinstalle depuis zéro à l'identique. **Règle : `npm install` en local (quand tu changes volontairement une dépendance), `npm ci` partout en CI/CD.** C'est ce qui garantit que ce qui a été audité et relu est *exactement* ce qui part en prod.

### 2.5 Pinning et ranges semver

`MAJOR.MINOR.PATCH`. Les préfixes de range :

| Range | Signifie | Risque |
|---|---|---|
| `^1.2.3` | `>=1.2.3 <2.0.0` (minor + patch) | tire des versions futures non relues |
| `~1.2.3` | `>=1.2.3 <1.3.0` (patch seul) | plus étroit |
| `1.2.3` | **exactement** cette version (pinné) | reproductible, mais màj manuelle |
| `*` / `latest` | n'importe quoi | à bannir |

Nuance : **le lockfile fige déjà les versions exactes** pour un install donné, même avec des `^`. Le `^` redevient dangereux surtout quand *quelqu'un refait* un `npm install` (le lockfile bouge) ou quand il n'y a pas de lockfile. La ceinture et les bretelles : ranges raisonnables (`^`/`~`) **+ lockfile commité + `npm ci` en CI**, et pinning strict pour les dépendances les plus sensibles (build, sécurité).

### 2.6 Typosquatting

L'attaquant publie un paquet au nom **proche** d'un paquet populaire, en pariant sur une faute de frappe :

```
lodash     → lodahs, 1odash        react   → recat, reactt
express    → expres, expreess      cross-env → crossenv
```

Avant d'ajouter un paquet, vérifie : téléchargements hebdo, âge, mainteneur (2FA ? orga vérifiée ?), lien vers un dépôt source actif, nombre de dépendances transitives. Un paquet récent, sans dépôt, à un seul mainteneur, qui « ressemble » à un paquet connu = **stop**.

### 2.7 Dependency confusion (attaque par substitution)

Faille de **résolution**, pas de faute de frappe. Tu as un paquet **interne** `@tribuzen/ui-kit`. Si ton `npm install` interroge **à la fois** ton registre privé et le registre public, et qu'un attaquant publie `@tribuzen/ui-kit` avec un **numéro de version plus élevé** sur le registre public, le résolveur peut choisir la version publique **malveillante**.

Défenses (OWASP / docs npm) :

1. **Scopes** (`@tribuzen/...`) + `.npmrc` qui **épingle le scope à ton registre privé** — le plus efficace :
   ```ini
   # .npmrc
   @tribuzen:registry=https://registry.interne.tribuzen.app/
   ```
2. **Claim ton scope** sur npmjs.com même sans publier — personne d'autre ne peut publier sous `@tribuzen/`.
3. **Registre unique** via un proxy (Verdaccio, Nexus, Artifactory) configuré pour ne chercher le public que pour les paquets explicitement publics.
4. **Lockfile** — le champ `resolved` fige le registre d'origine, ce qui coupe l'« upgrade » silencieux vers le public.

### 2.8 Lifecycle scripts (`preinstall` / `postinstall`)

`preinstall`, `install`, `postinstall` s'exécutent **automatiquement** pendant `npm install`, avec **tes droits** — c'est le vecteur d'exécution favori d'un paquet malveillant.

```bash
# Installer SANS exécuter les scripts (audit d'un paquet suspect, ou politique globale)
npm install --ignore-scripts
npm config set ignore-scripts true    # défaut global ; relancer manuellement les scripts de confiance
npm rebuild                           # recompile les binaires natifs de confiance après coup

# Inspecter AVANT d'installer
npm view <pkg> scripts                # affiche les scripts déclarés
npm pack <pkg> --dry-run              # liste le contenu du tarball sans l'installer
```

`--ignore-scripts` casse les paquets qui compilent du natif (ex. certains binaires) — d'où le `npm rebuild` ciblé ensuite. En CI, `--ignore-scripts` est un durcissement fort si ton build n'en dépend pas.

### 2.9 SBOM : l'inventaire

Un **SBOM** (Software Bill of Materials) est la **liste exhaustive** de tout ce que ton app embarque — indispensable pour répondre « suis-je affecté ? » quand une CVE tombe (souviens-toi de Log4Shell). npm en génère un nativement :

```bash
npm sbom --sbom-format cyclonedx     # format CycloneDX (orienté sécurité)
npm sbom --sbom-format spdx          # format SPDX (orienté conformité/licences)
```

Deux standards : **CycloneDX** (compact, support natif des vulnérabilités) et **SPDX** (orienté licences/conformité). Outil de référence côté npm : `@cyclonedx/cyclonedx-npm`.

### 2.10 Provenance & signatures

La **provenance** répond à « ce paquet a-t-il vraiment été construit depuis ce code source, par ce pipeline ? ». À la publication, `npm publish --provenance` (depuis un CI cloud) génère une **attestation** liant le paquet à son **code source** et à ses **instructions de build**, signée via **Sigstore** (certificats éphémères + journal public infalsifiable), en s'appuyant sur l'**OIDC** du CI. Prérequis : runner cloud (GitHub Actions / GitLab CI), npm CLI ≥ 9.5.0, URL de dépôt public dans `package.json` correspondant au CI.

Côté **consommateur** (toi), la vérification se fait avec :

```bash
npm audit signatures    # vérifie signatures de registre + attestations de provenance des dépendances installées
```

### 2.11 Automatiser : Dependabot / Renovate + CI

- **Dependabot / Renovate** ouvrent des PR de mise à jour (patch/minor/major séparés) et signalent les alertes de sécurité.
- **La CI est le garde-fou** : `npm ci` + `npm audit --audit-level=high` + tests + build. Une màj auto ne merge que si la porte passe (voir Worked example 2).

---

## 3. Worked examples

### Exemple 1 — Durcir `package.json` + install (TribuZen)

On reprend le §1 et on bouche les cinq trous.

```jsonc
// package.json — APRÈS durcissement
{
  "name": "tribuzen-api",
  "dependencies": {
    "express": "^4.18.2",          // (1) range gardé MAIS lockfile commité + npm ci en CI
    "cross-env": "~7.0.3",         // (2) "*" remplacé par une borne stricte (~ = patch seul)
    "@tribuzen/ui-kit": "^2.1.0"   // (4) interne : voir .npmrc ci-dessous (scope épinglé)
    // (3) "colors" au nom exotique : retiré après vérif (âge, mainteneur, dépôt) — typosquat/sabotage
  }
}
```

```ini
# .npmrc — (4) coupe la dependency confusion : le scope interne ne vient QUE du registre privé
@tribuzen:registry=https://registry.interne.tribuzen.app/
```

```bash
# (5) Investiguer le postinstall inconnu AVANT de faire tourner quoi que ce soit
npm install --ignore-scripts            # installe sans exécuter les lifecycle scripts
npm ls react-helper                     # d'où vient ce paquet ? (dépendance transitive de qui ?)
npm view react-helper scripts           # que fait son postinstall ?
# → si malveillant : retirer la dépendance qui l'introduit, régénérer le lockfile, re-auditer

# Puis, chaîne saine :
npm audit --audit-level=high            # porte : échoue à partir de "high"
npm ci                                  # install reproductible depuis le lockfile (en CI)
```

Ce qui a changé : plus de `"*"`, scope interne épinglé (anti-confusion), paquet suspect retiré, scripts d'install neutralisés le temps de l'audit, `npm audit` en porte et `npm ci` pour un install reproductible.

### Exemple 2 — Porte de sécurité supply chain en CI (GitHub Actions)

```yaml
# .github/workflows/supply-chain.yml
name: Supply chain gate
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm

      # Install REPRODUCTIBLE : échoue si package.json et lockfile divergent
      - name: Install (lockfile strict)
        run: npm ci

      # Porte bloquante : la CI échoue à partir d'une vuln "high"
      - name: Audit dependencies
        run: npm audit --audit-level=high

      # Vérifie les signatures/provenance des dépendances installées
      - name: Verify signatures & provenance
        run: npm audit signatures

      # Inventaire versionné à chaque build (répondre vite à la prochaine CVE)
      - name: Generate SBOM
        run: npm sbom --sbom-format cyclonedx > sbom.cyclonedx.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.cyclonedx.json
```

Points clés : `npm ci` (pas `install`) garantit que la CI teste **exactement** le lockfile relu ; `npm audit` en étape séparée **bloque** le merge sur une vuln high ; le SBOM est archivé pour l'après-coup.

---

## 4. Pièges & misconceptions

### PIÈGE #1 — « `npm audit` clean = je suis en sécurité »
Faux. `npm audit` ne connaît que les **CVE publiées**. Un typosquat ou un paquet saboté **hier** n'a pas encore d'advisory. L'audit détecte le *connu vulnérable*, pas le *malveillant frais*. Complète par la revue des nouveaux paquets, `--ignore-scripts`, et un outil comportemental (SCA).

### PIÈGE #2 — Ne pas commiter (ou ignorer) le lockfile
Sans lockfile commité, chaque `npm install` peut résoudre un arbre différent → une version compromise entre sans revue, et « ça marche chez moi » devient ingérable. Le lockfile **se commit toujours**, et la CI l'impose via `npm ci`.

### PIÈGE #3 — `npm install` en CI
`npm install` peut **modifier** le lockfile en CI : tu testes alors autre chose que ce qui a été relu, et une résolution silencieuse peut tirer une version non auditée. En CI, **toujours `npm ci`** (échoue si lockfile et `package.json` divergent).

### PIÈGE #4 — `npm audit fix --force` en aveugle
`--force` autorise les sauts **semver-major** : il « corrige » la vuln mais peut **casser** ton app (breaking changes). Lis le diff, teste, puis merge. `fix --force` n'est pas un bouton magique.

### PIÈGE #5 — Confondre typosquatting et dependency confusion
**Typosquatting** = tu te trompes de **nom** (`lodahs`). **Dependency confusion** = le **bon nom** interne (`@tribuzen/ui-kit`) est résolu depuis le **mauvais registre** (public) parce qu'une version plus haute y existe. Parades différentes : vérif du nom vs. scope épinglé + registre unique.

### PIÈGE #6 — Laisser les lifecycle scripts s'exécuter sans y penser
`postinstall` s'exécute **automatiquement** avec tes droits dès `npm install`. Un paquet transitif malveillant n'a pas besoin que tu l'importes dans le code pour agir. Inspecter avec `npm view <pkg> scripts`, et durcir avec `--ignore-scripts` (+ `npm rebuild` ciblé) quand le build ne dépend pas des scripts.

### PIÈGE #7 — Croire que la provenance chiffre ou protège le contenu
La **provenance** ne rend pas un paquet « sûr » : elle **prouve l'origine** (quel code source, quel pipeline). Un mainteneur malveillant peut publier du code malveillant *avec* une provenance valide. C'est une garantie d'**intégrité/traçabilité**, pas d'innocuité.

---

## 5. Ancrage TribuZen

TribuZen manipule des **données de familles et de mineurs** : une seule dépendance compromise dans le back-office peut exfiltrer une base entière. La supply chain n'est donc pas un « nice to have ».

Où ça vit dans `smaurier/tribuzen` :

```
tribuzen/
  .npmrc                        ← @tribuzen épinglé au registre privé (anti-dependency-confusion)
  package.json                  ← ranges maîtrisés, pas de "*", scripts sous contrôle
  package-lock.json             ← COMMITÉ : versions exactes + integrity SHA-512
  .github/workflows/
    supply-chain.yml            ← npm ci + npm audit --audit-level=high + audit signatures + SBOM
  renovate.json                 ← PR de màj auto (patch/minor), major en revue manuelle
  security/
    sbom.cyclonedx.json         ← inventaire archivé à chaque build
```

Points d'ancrage concrets :
- **Front + back-office** : mêmes garde-fous (`npm ci`, audit high, SBOM) sur les deux paquets.
- **`@tribuzen/ui-kit`** (design system interne) : scope épinglé, scope claimé sur npm — pas de substitution possible.
- **CI** : `npm audit` bloquant, `npm audit signatures` pour vérifier la provenance des dépendances critiques.
- **Secrets, registre privé auto-hébergé, TLS** → **module 10**, pas ici.

---

## 6. Points clés

1. Une attaque supply chain compromet une **dépendance** (souvent **transitive**) qui tourne avec les droits de ton app — c'est A06 + A08 de l'OWASP Top 10.
2. `npm audit` interroge le registre pour les **CVE connues** ; `--audit-level=high` en fait une porte CI. Il ne voit **pas** le malveillant frais.
3. Le **lockfile** fige versions exactes (`resolved`) + intégrité (`integrity` SHA-512) : **commité toujours**, imposé en CI par **`npm ci`** (jamais `npm install`).
4. **Pinning/ranges** : bannir `"*"` ; `^`/`~` raisonnables + lockfile + `npm ci` ; pinning strict pour les dépendances sensibles.
5. **Typosquatting** (mauvais nom) ≠ **dependency confusion** (bon nom, mauvais registre) : parades = vérif du paquet vs. scope épinglé + registre unique + claim de scope.
6. Les **lifecycle scripts** (`postinstall`) s'exécutent automatiquement : inspecter (`npm view … scripts`), durcir (`--ignore-scripts` + `npm rebuild`).
7. **SBOM** (`npm sbom`, CycloneDX/SPDX) = inventaire pour répondre vite à la prochaine CVE ; **provenance** (`--provenance` / `npm audit signatures`) = preuve d'origine via Sigstore, **pas** de garantie d'innocuité.
8. Automatiser (Renovate/Dependabot) **et** garder la CI comme garde-fou : `npm ci` + `npm audit` + tests avant merge.

---

## 7. Seeds Anki

```
Pourquoi une dépendance transitive est-elle un risque de sécurité ?|Tu ne l'as jamais choisie (c'est une dépendance de tes dépendances), mais elle s'exécute avec les mêmes droits que ton app. Une app npm moyenne en tire des centaines.
Que garantit package-lock.json et via quels champs ?|Un install reproductible à l'identique. resolved = l'emplacement exact d'où le paquet vient (registre) ; integrity = un hash SHA-512 (SRI) qui fait échouer l'install si le contenu diffère.
npm ci vs npm install — lequel en CI et pourquoi ?|npm ci en CI : il installe EXACTEMENT le lockfile, ignore les ranges, et échoue si package.json et lockfile divergent. npm install peut modifier le lockfile → on testerait autre chose que ce qui a été relu.
Typosquatting vs dependency confusion ?|Typosquatting = mauvais NOM proche d'un paquet connu (lodahs). Dependency confusion = BON nom interne (@org/x) résolu depuis le MAUVAIS registre (public) car une version plus haute y existe. Parades : vérif du nom vs. scope épinglé + registre unique.
Comment se protéger de la dependency confusion sur un paquet interne ?|Scoper (@org/pkg) et épingler le scope au registre privé dans .npmrc ; claimer le scope sur npmjs.com ; registre unique via proxy ; le lockfile (resolved) fige le registre d'origine.
Quel est le danger d'un script postinstall et comment le neutraliser ?|preinstall/postinstall s'exécutent automatiquement pendant npm install avec tes droits — un paquet transitif malveillant agit sans que tu l'importes. Parade : npm install --ignore-scripts (+ npm rebuild ciblé), inspecter via npm view <pkg> scripts.
npm audit détecte-t-il un paquet malveillant fraîchement publié ?|Non. Il ne connaît que les CVE déjà publiées. Un typosquat ou un sabotage récent n'a pas encore d'advisory. L'audit est nécessaire mais pas suffisant.
Qu'est-ce qu'un SBOM et à quoi sert-il ?|Software Bill of Materials : l'inventaire exhaustif des dépendances de l'app (npm sbom, format CycloneDX ou SPDX). Sert à répondre vite à "suis-je affecté ?" quand une nouvelle CVE tombe.
Que prouve la provenance npm — et que ne prouve-t-elle PAS ?|Elle prouve l'ORIGINE : le paquet a été construit depuis ce code source par ce pipeline CI (signé via Sigstore/OIDC), vérifiable avec npm audit signatures. Elle ne prouve PAS que le code est inoffensif — un mainteneur malveillant peut publier du malware avec une provenance valide.
Que fait npm audit fix --force et quel est le piège ?|Il autorise des mises à jour semver-MAJOR pour corriger une vuln, donc des breaking changes probables. Piège : l'appliquer en aveugle casse l'app. Lire le diff, tester, puis merger.
```

---

## Pont vers le lab

> Lab associé : `labs/lab-09-supply-chain/README.md`. Exercice **défensif** : auditer les dépendances de TribuZen (npm audit, lockfile, `npm ci`), fermer une dependency confusion via scope + `.npmrc`, neutraliser un `postinstall` suspect, et brancher la porte de sécurité supply chain en CI. Vrais outils npm, zéro harnais simulé. Corrigé commenté + variante J+30.
