# Lab 09 — Auditer et durcir la supply chain de TribuZen

<!-- FLAG-REVIEW: SÉCURITÉ — à valider par Sylvain -->

> **Outcome :** à la fin, tu sais auditer les dépendances npm d'un projet réel (`npm audit`), verrouiller les installs (lockfile + `npm ci`), fermer une **dependency confusion** (scope + `.npmrc`), neutraliser un **`postinstall`** suspect, et brancher une **porte de sécurité supply chain en CI**.
> **Vrai outil :** npm (CLI ≥ 9) + un vrai projet Node — `npm audit`, `npm ci`, `npm ls`, `npm view`, `npm sbom`. **Aucun harnais simulé.**
> **Feedback :** le coach valide en session — pas de test-runner auto-correcteur.
>
> **Angle : DÉFENSIF.** Tu **audites et durcis TON propre projet**. Tu ne publies aucun paquet malveillant et n'attaques aucun registre tiers.

---

## Énoncé

Tu reprends `tribuzen-api`, le back-office qui manipule des **données de mineurs**. Sécurité supply chain jamais faite. On te donne un `package.json` volontairement fragile — **ton job = le durcir et prouver que la chaîne est saine.**

Crée un dossier de travail et démarre depuis ce `package.json` (starter réaliste, à copier tel quel) :

```jsonc
// package.json — starter fragile (à durcir)
{
  "name": "tribuzen-api",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "cross-env": "*",
    "@tribuzen/ui-kit": "^2.1.0"
  },
  "scripts": {
    "postinstall": "node scripts/setup.js"
  }
}
```

> Tu peux travailler sur ce starter **ou** sur un vrai dépôt existant (Collabenable, un side-project). L'important est d'exécuter les **vraies** commandes npm et de lire les **vrais** rapports. Pas de gap-fill.

### Objectif (cahier des charges exact)

1. **Auditer** les dépendances et lire le rapport (`npm audit`), classer par sévérité.
2. **Verrouiller** : générer/committer le lockfile, expliquer `resolved` + `integrity`, et prouver que `npm ci` échoue si tu désynchronises `package.json` et le lockfile.
3. **Fermer la dependency confusion** sur `@tribuzen/ui-kit` : créer un `.npmrc` qui épingle le scope à un registre privé.
4. **Neutraliser les lifecycle scripts** : installer sans exécuter les scripts, inspecter un `postinstall`, décider quoi faire.
5. **Brancher la porte CI** : un workflow qui fait `npm ci` + `npm audit --audit-level=high` + `npm audit signatures` + génère un SBOM.

---

## Étapes (en friction)

1. **Audit.** Lance `npm install` puis `npm audit`. Combien de vulnérabilités, à quelles sévérités ? Lance `npm audit --audit-level=high` et observe le **code de sortie** (`echo $LASTEXITCODE` en PowerShell / `echo $?` en bash). Explique à voix haute pourquoi ce code de sortie rend l'audit utilisable en CI.
2. **Lockfile.** Ouvre `package-lock.json`. Trouve une entrée de paquet et repère `resolved` et `integrity`. Explique ce que garantit chacun. Commit le lockfile.
3. **Prouve `npm ci`.** Modifie une version dans `package.json` **sans** régénérer le lockfile, puis lance `npm ci`. Que se passe-t-il ? Compare avec `npm install`. Conclus sur « quelle commande en CI ».
4. **Bannir `"*"`.** Remplace `"cross-env": "*"` par une borne stricte (`~x.y.z`). Explique le risque de `"*"`.
5. **Dependency confusion.** `@tribuzen/ui-kit` est **interne**. Écris un `.npmrc` qui force ce scope à venir **uniquement** d'un registre privé. Explique le scénario d'attaque que ça bloque.
6. **Lifecycle scripts.** Réinstalle avec `--ignore-scripts`. Inspecte les scripts d'un paquet avec `npm view <pkg> scripts`. Que ferais-tu si un `postinstall` transitif lançait un `curl … | sh` ?
7. **Cartographie.** `npm ls --all` (ou `npm ls <pkg>`) : d'où vient une dépendance transitive donnée ? Repère une dépendance que tu ne reconnais pas.
8. **SBOM.** Génère `npm sbom --sbom-format cyclonedx`. À quoi te servira ce fichier le jour où une CVE critique tombe sur un paquet transitif ?
9. **Porte CI.** Écris `.github/workflows/supply-chain.yml` : `npm ci` + `npm audit --audit-level=high` + `npm audit signatures` + SBOM archivé.

---

## Corrigé complet commenté

### 1–4. Audit, lockfile, `npm ci`, ranges

```bash
# 1. Audit — rapport + porte
npm install
npm audit                       # rapport complet, classé par sévérité (low → critical)
npm audit --audit-level=high    # exit ≠ 0 SEULEMENT à partir de "high" → utilisable comme porte CI
# En PowerShell : $LASTEXITCODE  |  En bash : echo $?
# Sévérité = échelle CVSS : critical 9-10, high 7-8.9, moderate 4-6.9, low 0.1-3.9

# 3. Preuve npm ci : désynchronise puis installe
#   → si package.json et package-lock.json divergent, npm ci ÉCHOUE (au lieu de "réparer" en douce)
npm ci
#   npm error `npm ci` can only install packages when your package.json and
#   package-lock.json are in sync. ...
# npm install, lui, aurait modifié le lockfile silencieusement → à proscrire en CI.
```

```jsonc
// 2. package-lock.json — les deux champs qui font la sécurité
"node_modules/express": {
  "version": "4.18.2",
  "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz", // OÙ : registre exact
  "integrity": "sha512-...=="                                            // QUOI : hash SHA-512 (SRI)
  // Si le tarball téléchargé ne matche pas l'integrity → l'install ÉCHOUE.
}
```

```jsonc
// 4. package.json — "*" banni, borne stricte
"cross-env": "~7.0.3"   // ~ = patch seul (>=7.0.3 <7.1.0). "*" acceptait N'IMPORTE quelle version.
```

### 5. Fermer la dependency confusion

```ini
# .npmrc — le scope @tribuzen ne vient QUE du registre privé.
# Scénario bloqué : un attaquant publie @tribuzen/ui-kit@99.0.0 sur le registre PUBLIC ;
# sans cette ligne, npm pourrait résoudre la version publique (plus haute) = code malveillant.
@tribuzen:registry=https://registry.interne.tribuzen.app/
//registry.interne.tribuzen.app/:_authToken=${NPM_TOKEN}   # jeton via env, jamais commité
```

> Compléter (hors lab, module 10 pour l'infra) : **claimer** le scope `@tribuzen` sur npmjs.com et passer par un **proxy** de registre unique.

### 6. Lifecycle scripts

```bash
# Installer SANS exécuter preinstall/postinstall (audit sûr d'un paquet suspect)
npm install --ignore-scripts

# Inspecter les scripts déclarés d'un paquet AVANT de lui faire confiance
npm view <pkg> scripts        # affiche { postinstall: "...", ... }
npm pack <pkg> --dry-run      # liste le contenu du tarball sans installer

# Si un postinstall transitif fait "curl https://… | sh" :
#   1) npm ls <pkg-malveillant>  → identifier QUELLE dépendance directe l'introduit
#   2) retirer/remplacer cette dépendance, régénérer le lockfile, re-auditer
#   3) durcissement durable : npm config set ignore-scripts true + npm rebuild ciblé au besoin
```

### 7–8. Cartographie + SBOM

```bash
npm ls --all                              # arbre complet ; d'où vient chaque transitive
npm ls cross-env                          # chemin d'une dépendance précise
npm sbom --sbom-format cyclonedx > sbom.cyclonedx.json   # inventaire (CycloneDX)
# Le jour d'une CVE : grep le nom du paquet vulnérable dans le SBOM → "affecté ou non ?" en secondes
```

### 9. Porte de sécurité supply chain en CI

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

      - name: Install (lockfile strict)
        run: npm ci                          # échoue si package.json / lockfile divergent

      - name: Audit dependencies
        run: npm audit --audit-level=high    # PORTE : bloque le merge sur une vuln high+

      - name: Verify signatures & provenance
        run: npm audit signatures            # signatures registre + attestations de provenance

      - name: Generate SBOM
        run: npm sbom --sbom-format cyclonedx > sbom.cyclonedx.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.cyclonedx.json
```

**Pourquoi ce corrigé est correct :**
- `npm ci` (pas `install`) → la CI teste **exactement** le lockfile relu ; toute divergence casse le build au lieu de la masquer.
- `npm audit --audit-level=high` est une **étape séparée bloquante** : une vuln high fait échouer la PR.
- `npm audit signatures` vérifie l'**origine** (provenance/signatures) des dépendances, pas seulement les CVE.
- Le SBOM archivé permet de répondre à la **prochaine** CVE sans re-scanner tout le monde.

---

## Grille d'auto-évaluation

| Critère | Acquis si… |
|---|---|
| Audit | tu lis un rapport `npm audit`, classes par sévérité CVSS, et sais ce que `--audit-level` change au **code de sortie** |
| Lockfile | tu expliques `resolved` **et** `integrity` (SHA-512), et pourquoi le lockfile se **commit** |
| `npm ci` | tu as **provoqué** l'échec de `npm ci` sur une désync et sais pourquoi c'est `npm ci` en CI |
| Ranges | tu as banni `"*"` et justifié `^` vs `~` vs pin strict |
| Dependency confusion | ton `.npmrc` épingle le scope interne et tu décris le scénario d'attaque bloqué |
| Lifecycle scripts | tu installes avec `--ignore-scripts`, inspectes un `postinstall` et sais tracer la dépendance fautive |
| SBOM / provenance | tu génères un SBOM et distingues **provenance = origine** ≠ **innocuité** |
| CI | ta porte fait `npm ci` + `npm audit` bloquant + `audit signatures` + SBOM |

---

## Coach — conduite de session

- **Ne donne pas les commandes d'emblée.** Demande d'abord : « comment saurais-tu si une de tes dépendances a une CVE connue ? » — laisse chercher `npm audit`.
- **Point de friction #1 (le plus formateur) :** fais **provoquer** l'échec de `npm ci` en désynchronisant à la main. Tant que Sylvain ne l'a pas vu échouer, la règle « ci ≠ install » reste abstraite.
- **Piège à débusquer :** s'il conclut « `npm audit` est clean donc je suis safe », relance avec le typosquat/sabotage récent (colors.js 2022) → l'audit ne voit que le **connu**.
- **Discrimination clé à vérifier :** typosquatting (mauvais **nom**) vs dependency confusion (bon nom, mauvais **registre**). S'il confond, reprends l'exemple `@tribuzen/ui-kit`.
- **Ancrage émotionnel TribuZen :** rappeler que c'est le back-office **des données de mineurs** — une dépendance compromise = exfiltration de la base. Le durcissement n'est pas cosmétique.
- **Si silence / blocage :** propose de commencer par le SBOM (`npm sbom`) — commande sans risque, résultat visible, qui débloque la discussion « qu'est-ce que j'embarque au juste ? ».

---

## Variante J+30 (fading)

**Même objectif, +2 contraintes, sans rouvrir ce corrigé ni le module 09 :**

1. **En 30 min**, sur un **vrai dépôt à toi** (pas le starter) : produis un rapport écrit — nombre de vulns par sévérité, présence/validité du lockfile, `"*"` ou ranges dangereux, dépendances au `postinstall` suspect, et **une** recommandation priorisée.
2. **Ajoute la vérif de provenance** : lance `npm audit signatures` et interprète le résultat — combien de dépendances ont une provenance vérifiable, et **pourquoi ça ne suffit pas** à les déclarer sûres.

**Critère de réussite :** la porte CI (`npm ci` + `npm audit --audit-level=high`) tourne sur ce dépôt et le rapport tient sur une page, priorisé par sévérité.

---

## Application TribuZen

Dans le repo `smaurier/tribuzen`, le durcissement supply chain vit ici :

```
tribuzen/
  .npmrc                          ← @tribuzen épinglé au registre privé
  package-lock.json               ← commité (versions exactes + integrity)
  .github/workflows/
    supply-chain.yml              ← npm ci + audit high + audit signatures + SBOM
  renovate.json                   ← PR de màj auto ; major en revue manuelle
  security/sbom.cyclonedx.json    ← inventaire archivé
```

**Différences par rapport au lab :**
- Le registre privé et le jeton `NPM_TOKEN` seront de **vrais secrets** gérés côté infra (**module 10**), pas des placeholders.
- La porte CI s'applique aux **deux** paquets (front + back-office), pas à un seul.
- Renovate/Dependabot ouvriront les PR de màj — la porte CI reste le garde-fou avant merge.

**Commit cible :**
```
chore(security): durcir la supply chain — npm ci, audit high, .npmrc scope, SBOM en CI
```
