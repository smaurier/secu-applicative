import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Sécurité Applicative',
  description: 'Sécurité applicative fullstack : OWASP, injection, auth, crypto, headers, CORS, API, supply chain, audit',
  lang: 'fr-FR',
  srcDir: '.',

  vite: {
    server: {
      port: 5179,
      strictPort: false
    }
  },

  // Docs statiques : neutralise l'interpolation Vue `{{ }}` en prose (SSR).
  // NB : override `delimiters` retiré (il cassait le {{ }} du thème par défaut).
  // cf docs/curriculum/DETTE-vitepress-delimiters.md


  ignoreDeadLinks: true,

  // Refonte v1 : le cours vit dans modules/ + labs/. Anciens quizzes = archive exclue.
  srcExclude: ['quizzes/**'],

  themeConfig: {
    nav: [
      { text: 'Modules', link: '/modules/00-introduction-securite' },
      { text: 'Labs', link: '/labs/lab-00-introduction-securite/README' }
    ],

    sidebar: {
      '/modules/': [
        {
          text: 'Sécurité applicative',
          items: [
            { text: '00 · Introduction & modèle de menace', link: '/modules/00-introduction-securite' },
            { text: '01 · OWASP Top 10', link: '/modules/01-owasp-top10' },
            { text: '02 · Injection (SQLi, XSS)', link: '/modules/02-injection' },
            { text: '03 · Authentification', link: '/modules/03-authentification' },
            { text: '03b · OIDC & PKCE', link: '/modules/03b-oidc-pkce-client' },
            { text: '03c · WebAuthn & passkeys', link: '/modules/03c-webauthn-passkeys' },
            { text: '04 · Autorisation (RBAC, IDOR)', link: '/modules/04-autorisation' },
            { text: '05 · Cryptographie', link: '/modules/05-cryptographie' },
            { text: '06 · En-têtes de sécurité', link: '/modules/06-headers-securite' },
            { text: '07 · CORS', link: '/modules/07-cors' },
            { text: '08 · Sécurité des API', link: '/modules/08-api-security' },
            { text: '09 · Supply chain', link: '/modules/09-supply-chain' },
            { text: '10 · Sécurité infrastructure', link: '/modules/10-infrastructure-securite' },
            { text: '11 · Audit & pentest défensif', link: '/modules/11-audit-pentest' }
          ]
        }
      ],
      '/labs/': [
        {
          text: 'Labs — exercices défensifs',
          items: [
            { text: 'Lab 00 · Modèle de menace', link: '/labs/lab-00-introduction-securite/README' },
            { text: 'Lab 01 · OWASP Top 10', link: '/labs/lab-01-owasp-top10/README' },
            { text: 'Lab 02 · Injection', link: '/labs/lab-02-injection/README' },
            { text: 'Lab 03 · Authentification', link: '/labs/lab-03-authentification/README' },
            { text: 'Lab 03b · OIDC & PKCE', link: '/labs/lab-03b-oidc-pkce-client/README' },
            { text: 'Lab 03c · WebAuthn', link: '/labs/lab-03c-webauthn-passkeys/README' },
            { text: 'Lab 04 · Autorisation', link: '/labs/lab-04-autorisation/README' },
            { text: 'Lab 05 · Cryptographie', link: '/labs/lab-05-cryptographie/README' },
            { text: 'Lab 06 · En-têtes', link: '/labs/lab-06-headers-securite/README' },
            { text: 'Lab 07 · CORS', link: '/labs/lab-07-cors/README' },
            { text: 'Lab 08 · Sécurité API', link: '/labs/lab-08-api-security/README' },
            { text: 'Lab 09 · Supply chain', link: '/labs/lab-09-supply-chain/README' },
            { text: 'Lab 10 · Infrastructure', link: '/labs/lab-10-infrastructure/README' },
            { text: 'Lab 11 · Audit', link: '/labs/lab-11-audit-pentest/README' }
          ]
        }
      ]
    },

    search: {
      provider: 'local'
    },

    outline: {
      level: [2, 3],
      label: 'Sur cette page'
    },

    docFooter: {
      prev: 'Précédent',
      next: 'Suivant'
    }
  }
})
