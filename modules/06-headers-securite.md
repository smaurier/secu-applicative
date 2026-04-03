# Module 06 — En-têtes HTTP de Sécurité

## Objectifs pédagogiques

- Comprendre le rôle des en-têtes HTTP dans la défense en profondeur
- Configurer Content-Security-Policy (CSP) de manière progressive
- Mettre en place HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Utiliser helmet.js pour automatiser la configuration
- Auditer les en-têtes d'une application en production

---

## 1. Pourquoi les en-têtes HTTP de sécurité sont importants

Les en-têtes HTTP de sécurité constituent une **couche de défense côté navigateur**. Ils indiquent au navigateur comment se comporter face à certaines situations : exécution de scripts, chargement de ressources, encadrement dans une iframe, etc.

Sans ces en-têtes, le navigateur applique des comportements par défaut souvent **permissifs**, ce qui facilite les attaques XSS, clickjacking, sniffing MIME, etc.

> **Principe de défense en profondeur** : même si votre code est sécurisé, les en-têtes ajoutent une barrière supplémentaire en cas de faille.

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

---

## 2. Content-Security-Policy (CSP)

CSP est **l'en-tête de sécurité le plus puissant**. Il contrôle quelles ressources le navigateur est autorisé à charger et exécuter.

### 2.1 Directives principales

| Directive | Rôle |
|---|---|
| `default-src` | Fallback pour toutes les directives non spécifiées |
| `script-src` | Sources autorisées pour les scripts |
| `style-src` | Sources autorisées pour les feuilles de style |
| `img-src` | Sources autorisées pour les images |
| `connect-src` | Sources pour XHR, fetch, WebSocket |
| `font-src` | Sources pour les polices de caractères |
| `frame-src` | Sources pour les iframes |
| `frame-ancestors` | Qui peut encadrer cette page dans une iframe |
| `object-src` | Sources pour `<object>`, `<embed>`, `<applet>` |
| `base-uri` | Restreint les URLs utilisables dans `<base>` |
| `form-action` | Restreint les cibles de `<form action>` |

### 2.2 Valeurs de source

```
'self'          → même origine
'none'          → rien autorisé
'unsafe-inline' → scripts/styles inline (à éviter)
'unsafe-eval'   → eval(), new Function() (à éviter)
https:          → toute URL HTTPS
*.example.com   → sous-domaines de example.com
'nonce-abc123'  → scripts avec le nonce spécifié
'sha256-...'    → scripts correspondant au hash
```

### 2.3 Exemple de CSP stricte

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https://cdn.example.com;
  connect-src 'self' https://api.example.com;
  font-src 'self';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self'
```

### 2.4 Nonces et hashes pour inline scripts

Plutôt que d'utiliser `'unsafe-inline'`, utilisez des **nonces** (valeurs aléatoires par requête) :

```typescript
import { randomBytes } from 'crypto';
import express, { Request, Response, NextFunction } from 'express';

const app = express();

app.use((req: Request, res: Response, next: NextFunction) => {
  // Générer un nonce unique par requête
  const nonce = randomBytes(16).toString('base64');
  res.locals.cspNonce = nonce;

  res.setHeader(
    'Content-Security-Policy',
    `default-src 'self'; script-src 'self' 'nonce-${nonce}'`
  );
  next();
});

app.get('/', (req: Request, res: Response) => {
  const nonce = res.locals.cspNonce;
  res.send(`
    <html>
      <body>
        <script nonce="${nonce}">
          console.log('Script autorisé par le nonce');
        </script>
      </body>
    </html>
  `);
});
```

Pour les **hashes** (contenu statique connu à l'avance) :

```
Content-Security-Policy: script-src 'sha256-B2yPHKaXnvFWtRChIbabYmUBFZdVfKKXHbWtWidDVF8='
```

Le hash se calcule sur le contenu exact du script inline (sans les balises `<script>`).

### 2.5 Reporting CSP

CSP peut **rapporter** les violations sans bloquer (mode audit) :

```
Content-Security-Policy-Report-Only:
  default-src 'self';
  report-uri /api/csp-report;
  report-to csp-endpoint
```

En-tête `Report-To` pour la nouvelle API Reporting :

```
Report-To: {"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"/api/csp-report"}]}
```

Endpoint pour collecter les rapports :

```typescript
app.post('/api/csp-report', express.json({ type: 'application/csp-report' }), (req, res) => {
  const report = req.body['csp-report'];
  console.warn('CSP Violation:', {
    blockedUri: report['blocked-uri'],
    violatedDirective: report['violated-directive'],
    documentUri: report['document-uri'],
  });
  res.status(204).end();
});
```

### 2.6 Migration progressive

1. **Phase 1** : Déployer en `Report-Only` pour observer les violations
2. **Phase 2** : Corriger les violations (externaliser les scripts inline, etc.)
3. **Phase 3** : Passer en mode bloquant (`Content-Security-Policy`)
4. **Phase 4** : Resserrer progressivement les directives

---

## 3. Strict-Transport-Security (HSTS)

HSTS force le navigateur à **toujours utiliser HTTPS** pour le domaine, même si l'utilisateur tape `http://`.

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

| Paramètre | Rôle |
|---|---|
| `max-age` | Durée (en secondes) pendant laquelle le navigateur force HTTPS |
| `includeSubDomains` | Applique aussi aux sous-domaines |
| `preload` | Demande l'inclusion dans la liste HSTS preload des navigateurs |

### HSTS Preload List

La [HSTS Preload List](https://hstspreload.org/) est intégrée directement dans les navigateurs. Une fois inscrit, votre domaine est **toujours** en HTTPS, même lors de la première visite.

> ⚠️ L'inscription est **difficile à annuler**. Assurez-vous que HTTPS fonctionne parfaitement sur tous vos sous-domaines avant de vous inscrire.

---

## 4. X-Content-Type-Options

```
X-Content-Type-Options: nosniff
```

Empêche le navigateur de **deviner** le type MIME d'une ressource. Sans cet en-tête, un fichier texte contenant du JavaScript pourrait être interprété comme un script.

---

## 5. X-Frame-Options vs frame-ancestors

### X-Frame-Options (ancien)

```
X-Frame-Options: DENY          # Interdit tout encadrement
X-Frame-Options: SAMEORIGIN    # Autorise seulement la même origine
```

### CSP frame-ancestors (moderne)

```
Content-Security-Policy: frame-ancestors 'none'                    # Équivaut à DENY
Content-Security-Policy: frame-ancestors 'self'                    # Équivaut à SAMEORIGIN
Content-Security-Policy: frame-ancestors 'self' https://trusted.com  # Plus flexible
```

> **Recommandation** : Utilisez `frame-ancestors` dans CSP mais gardez `X-Frame-Options` pour la rétrocompatibilité.

---

## 6. Referrer-Policy

Contrôle quelles informations de l'URL référente sont envoyées dans l'en-tête `Referer` :

```
Referrer-Policy: strict-origin-when-cross-origin
```

| Valeur | Comportement |
|---|---|
| `no-referrer` | Aucun referer envoyé |
| `origin` | Envoie seulement l'origine (pas le chemin) |
| `same-origin` | Referer complet pour même origine, rien sinon |
| `strict-origin` | Origine seulement, et rien en downgrade HTTPS→HTTP |
| `strict-origin-when-cross-origin` | Complet pour même origine, origine pour cross-origin |
| `no-referrer-when-downgrade` | Pas de referer en downgrade HTTPS→HTTP |

---

## 7. Permissions-Policy

Anciennement `Feature-Policy`, cet en-tête contrôle l'accès aux APIs du navigateur :

```
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

```
Permissions-Policy: camera=(self), geolocation=(self "https://maps.example.com")
```

Désactiver les fonctionnalités inutilisées réduit la surface d'attaque si un script malveillant est injecté.

---

## 8. Configuration avec helmet.js

[helmet](https://helmetjs.github.io/) configure automatiquement les en-têtes de sécurité pour Express et NestJS.

### Express

```typescript
import express from 'express';
import helmet from 'helmet';

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https://cdn.example.com"],
      connectSrc: ["'self'", "https://api.example.com"],
      frameAncestors: ["'none'"],
    },
  },
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true,
  },
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin',
  },
}));
```

### NestJS

```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
  }));

  await app.listen(3000);
}
bootstrap();
```

---

## 9. Audit des en-têtes

### SecurityHeaders.com

Le site [securityheaders.com](https://securityheaders.com) scanne vos en-têtes et attribue une note de A+ à F.

### Mozilla Observatory

[observatory.mozilla.org](https://observatory.mozilla.org) fournit un audit plus complet incluant les en-têtes, TLS, et d'autres bonnes pratiques.

### Vérification programmatique

```typescript
async function auditHeaders(url: string): Promise<void> {
  const response = await fetch(url);
  const headers = response.headers;

  const requiredHeaders = [
    'content-security-policy',
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
    'referrer-policy',
    'permissions-policy',
  ];

  for (const header of requiredHeaders) {
    const value = headers.get(header);
    if (value) {
      console.log(`✅ ${header}: ${value}`);
    } else {
      console.warn(`❌ ${header}: MANQUANT`);
    }
  }
}
```

---

## 10. Résumé

| En-tête | Protection |
|---|---|
| `Content-Security-Policy` | XSS, injection de ressources |
| `Strict-Transport-Security` | Downgrade HTTPS → HTTP |
| `X-Content-Type-Options` | MIME sniffing |
| `X-Frame-Options` / `frame-ancestors` | Clickjacking |
| `Referrer-Policy` | Fuite d'informations via Referer |
| `Permissions-Policy` | Accès non autorisé aux APIs navigateur |

> **Règle d'or** : Utilisez `helmet.js` comme point de départ, puis ajustez la CSP selon les besoins spécifiques de votre application.

---

## Exercice pratique

1. Créez une application Express avec `helmet` configuré
2. Ajoutez une CSP en mode `Report-Only` et collectez les violations
3. Corrigez les violations et passez en mode bloquant
4. Vérifiez votre score sur securityheaders.com
5. Ajoutez HSTS avec `preload` et vérifiez sur hstspreload.org

---

## Ressources

- [MDN — Content-Security-Policy](https://developer.mozilla.org/fr/docs/Web/HTTP/Headers/Content-Security-Policy)
- [Helmet.js Documentation](https://helmetjs.github.io/)
- [CSP Evaluator (Google)](https://csp-evaluator.withgoogle.com/)
- [HSTS Preload](https://hstspreload.org/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
