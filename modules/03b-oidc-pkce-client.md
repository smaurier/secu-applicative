# Module 3b — OIDC / OAuth2 côté client (PKCE flow)

| Difficulte | Duree estimee |
|------------|---------------|
| 3/5        | 60 min        |

> **Prérequis** : Module 03 (Authentification) — tu dois comprendre JWT, sessions et la distinction authn/authz avant d'aborder ce module.

## Objectifs

- Comprendre le flow PKCE côté navigateur (sans secret client)
- Implémenter login, callback, refresh token silencieux
- Gérer la déconnexion distribuée (logout global)
- Sécuriser les tokens en mémoire (pas dans localStorage)
- Intégrer un provider OIDC dans une app React/Vue/Angular

---

## Pourquoi PKCE et pas le flow classique

OAuth2 classique utilise un `client_secret`. Dans un SPA (Single Page Application), ce secret est exposé dans le code source — n'importe qui peut l'extraire depuis DevTools. PKCE (Proof Key for Code Exchange) résout ça sans secret : le client génère un `code_verifier` aléatoire et prouve qu'il était bien l'initiateur de la demande.

```
SPA                    Auth Server              API
 │                          │                    │
 │ 1. génère code_verifier  │                    │
 │    et code_challenge      │                    │
 │                          │                    │
 │──── /authorize ─────────►│                    │
 │    (+ code_challenge)     │                    │
 │                          │                    │
 │◄─── redirect + code ─────│                    │
 │                          │                    │
 │──── /token ─────────────►│                    │
 │    (code + code_verifier) │                    │
 │                          │                    │
 │◄─── access_token ────────│                    │
 │     + refresh_token       │                    │
 │                          │                    │
 │──────────────────────────────── requête API ──►│
 │                    (Authorization: Bearer ...)  │
```

---

## Implémentation PKCE de A à Z

### 1. Générer le code_verifier et code_challenge

```typescript
// src/auth/pkce.ts

export async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
  const verifier = generateRandomString(128);
  const challenge = await sha256Base64Url(verifier);
  return { verifier, challenge };
}

function generateRandomString(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => chars[b % chars.length]).join('');
}

async function sha256Base64Url(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
```

### 2. Initier le login

```typescript
// src/auth/oidc-client.ts

interface OIDCConfig {
  issuer: string;           // ex: 'https://accounts.google.com'
  clientId: string;
  redirectUri: string;
  scopes: string[];
}

export async function initiateLogin(config: OIDCConfig): Promise<void> {
  const { verifier, challenge } = await generatePKCE();

  // Stocker le verifier en mémoire (PAS localStorage) pour le callback
  sessionStorage.setItem('pkce_verifier', verifier);

  const state = generateRandomString(32);
  sessionStorage.setItem('oauth_state', state);

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scopes.join(' '),
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });

  window.location.href = `${config.issuer}/oauth2/authorize?${params}`;
}
```

### 3. Gérer le callback

```typescript
// src/auth/callback.ts

export async function handleCallback(config: OIDCConfig): Promise<TokenSet> {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');
  const error = params.get('error');

  if (error) throw new Error(`OAuth error: ${error} — ${params.get('error_description')}`);
  if (!code) throw new Error('No authorization code in callback');

  // Vérifier le state pour prévenir les attaques CSRF
  const savedState = sessionStorage.getItem('oauth_state');
  if (state !== savedState) throw new Error('State mismatch — possible CSRF');

  const verifier = sessionStorage.getItem('pkce_verifier');
  if (!verifier) throw new Error('No PKCE verifier found');

  // Nettoyer immédiatement
  sessionStorage.removeItem('pkce_verifier');
  sessionStorage.removeItem('oauth_state');

  // Échanger le code contre des tokens
  const response = await fetch(`${config.issuer}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: config.redirectUri,
      client_id: config.clientId,
      code_verifier: verifier,
    }),
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(`Token exchange failed: ${err.error}`);
  }

  return response.json() as Promise<TokenSet>;
}

interface TokenSet {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in: number;
  token_type: 'Bearer';
}
```

### 4. Stocker les tokens en mémoire (pas dans localStorage)

```typescript
// src/auth/token-store.ts

// Stockage en mémoire — disparait au refresh de page (voulu)
// Le refresh token en httpOnly cookie est l'alternative recommandée
let accessToken: string | null = null;
let refreshToken: string | null = null;
let expiresAt: number | null = null;

export const tokenStore = {
  set(tokens: TokenSet): void {
    accessToken = tokens.access_token;
    refreshToken = tokens.refresh_token ?? null;
    expiresAt = Date.now() + tokens.expires_in * 1000;
  },

  getAccessToken(): string | null {
    return accessToken;
  },

  isExpired(): boolean {
    if (!expiresAt) return true;
    return Date.now() > expiresAt - 30_000; // 30s de marge
  },

  clear(): void {
    accessToken = null;
    refreshToken = null;
    expiresAt = null;
  },

  getRefreshToken(): string | null {
    return refreshToken;
  },
};
```

### 5. Silent refresh (renouveler le token avant expiration)

```typescript
// src/auth/silent-refresh.ts

export async function silentRefresh(config: OIDCConfig): Promise<void> {
  const refresh = tokenStore.getRefreshToken();
  if (!refresh) throw new Error('No refresh token available');

  const response = await fetch(`${config.issuer}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refresh,
      client_id: config.clientId,
    }),
  });

  if (!response.ok) {
    // Refresh token expiré ou révoqué — forcer le login
    tokenStore.clear();
    throw new Error('Silent refresh failed — re-login required');
  }

  const tokens: TokenSet = await response.json();
  tokenStore.set(tokens);
}

// Intercepteur HTTP : si le token est expiré, rafraichit avant la requête
export async function fetchWithAuth(url: string, options: RequestInit = {}): Promise<Response> {
  if (tokenStore.isExpired()) {
    await silentRefresh(config); // config injectée via closure ou contexte
  }

  const token = tokenStore.getAccessToken();
  return fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: `Bearer ${token}`,
    },
  });
}
```

### 6. Logout distribué (global logout)

```typescript
// src/auth/logout.ts

export async function logout(config: OIDCConfig): Promise<void> {
  const idToken = tokenStore.getIdToken(); // stocker l'id_token au login
  tokenStore.clear();

  // Appeler l'endpoint logout du provider pour invalider la session SSO
  // Sans ça, l'utilisateur reste connecté sur le provider même si l'app oublie ses tokens
  const params = new URLSearchParams({
    post_logout_redirect_uri: config.redirectUri,
    ...(idToken ? { id_token_hint: idToken } : {}),
  });

  window.location.href = `${config.issuer}/oauth2/logout?${params}`;
}
```

---

## Intégration dans React

```typescript
// src/auth/AuthProvider.tsx

import { createContext, useContext, useEffect, useState } from 'react';

interface AuthContextValue {
  isAuthenticated: boolean;
  login: () => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    // Callback depuis le provider
    const params = new URLSearchParams(window.location.search);
    if (params.has('code')) {
      handleCallback(config)
        .then((tokens) => {
          tokenStore.set(tokens);
          setIsAuthenticated(true);
          // Nettoyer l'URL
          window.history.replaceState({}, '', window.location.pathname);
        })
        .catch(console.error);
    }
  }, []);

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        login: () => initiateLogin(config),
        logout: () => logout(config).then(() => setIsAuthenticated(false)),
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
};
```

---

## Alternatives : bibliothèques à connaître

En prod tu n'implémenteras pas ça from scratch — mais comprendre le flow permet de choisir et débugger.

| Lib | Usage | Points forts |
|-----|-------|-------------|
| `@auth0/auth0-react` | Auth0 provider | Clé en main, bien documenté |
| `oidc-client-ts` | Provider-agnostic | Léger, PKCE natif, TypeScript |
| `next-auth` | Next.js | Intégration serveur/client, multi-provider |
| `@azure/msal-browser` | Azure AD / Microsoft Entra | Obligatoire pour les clients Microsoft |
| Keycloak JS adapter | Keycloak (self-hosted) | Contexte ferroviaire / industriel fréquent |

> **Pour Alstom** : contexte Microsoft probable (Azure AD) ou Keycloak auto-hébergé. Les deux utilisent OIDC/PKCE — ce module s'applique directement.

---

## Erreurs courantes

```typescript
// ❌ Stocker l'access_token dans localStorage
localStorage.setItem('token', accessToken); // XSS → vol de token

// ✅ Mémoire uniquement (ou httpOnly cookie côté serveur)
tokenStore.set(tokens);

// ❌ Ignorer la vérification du state
const code = params.get('code'); // sans vérifier state → CSRF possible

// ✅ Toujours vérifier
if (state !== savedState) throw new Error('State mismatch');

// ❌ Logout local seulement
tokenStore.clear(); // l'utilisateur reste connecté sur le SSO provider

// ✅ Logout global
window.location.href = `${config.issuer}/logout?...`;
```

---

## Checklist

- [ ] Je comprends pourquoi PKCE remplace le client_secret dans les SPAs
- [ ] Je sais générer un code_verifier et code_challenge avec Web Crypto API
- [ ] Je sais gérer le callback OIDC (vérification state, échange code → tokens)
- [ ] Les tokens sont stockés en mémoire, pas dans localStorage
- [ ] Le silent refresh est implémenté avant expiration
- [ ] Le logout invalide la session SSO (pas juste les tokens locaux)
- [ ] Je connais les bibliothèques OIDC du marché (oidc-client-ts, MSAL, next-auth)
