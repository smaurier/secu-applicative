# Glossaire — Sécurité Applicative

## A

- **ABAC (Attribute-Based Access Control)** : Contrôle d'accès basé sur les attributs de l'utilisateur, de la ressource et du contexte. Permet des politiques d'autorisation fines et dynamiques, par exemple « un médecin peut accéder au dossier s'il est dans le même service ».

- **ACL (Access Control List)** : Liste de contrôle d'accès associée à une ressource, définissant quels utilisateurs ou groupes ont quelles permissions (lecture, écriture, suppression).

- **Argon2** : Algorithme de hachage de mots de passe vainqueur du Password Hashing Competition (2015). Résistant aux attaques par GPU et ASIC grâce à sa consommation mémoire configurable.

- **Attaque par force brute** : Technique consistant à essayer systématiquement toutes les combinaisons possibles d'un mot de passe ou d'une clé jusqu'à trouver la bonne. Contrée par le rate limiting, le verrouillage de compte et les CAPTCHAs.

- **Attaque par dictionnaire** : Variante de la force brute utilisant une liste de mots de passe courants ou compromis plutôt que toutes les combinaisons possibles.

## B

- **BCrypt** : Fonction de hachage de mots de passe basée sur l'algorithme Blowfish. Intègre un sel automatique et un facteur de coût ajustable pour ralentir les tentatives de craquage.

## C

- **Chiffrement asymétrique** : Système cryptographique utilisant une paire de clés (publique et privée). La clé publique chiffre, la clé privée déchiffre. Exemples : RSA, ECDSA, Ed25519.

- **Chiffrement symétrique** : Système cryptographique utilisant une seule clé partagée pour le chiffrement et le déchiffrement. Exemples : AES-256-GCM, ChaCha20-Poly1305.

- **CORS (Cross-Origin Resource Sharing)** : Mécanisme HTTP permettant à un serveur d'indiquer quelles origines sont autorisées à accéder à ses ressources. Contrôlé par les en-têtes `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, etc.

- **CSRF (Cross-Site Request Forgery)** : Attaque forçant un utilisateur authentifié à exécuter des actions non souhaitées sur une application web. Parade : tokens anti-CSRF, attribut `SameSite` sur les cookies.

- **CSP (Content Security Policy)** : En-tête HTTP spécifiant les sources autorisées pour les scripts, styles, images et autres ressources. Défense majeure contre les attaques XSS.

- **CVE (Common Vulnerabilities and Exposures)** : Identifiant unique attribué à une vulnérabilité de sécurité connue publiquement. Format : CVE-YYYY-NNNNN. Répertorié dans la base NVD (National Vulnerability Database).

- **CVSS (Common Vulnerability Scoring System)** : Système de notation standardisé évaluant la gravité d'une vulnérabilité sur une échelle de 0 à 10.

## D

- **DOM-based XSS** : Variante de XSS où le code malveillant est exécuté côté client via la manipulation du DOM, sans passer par le serveur. Sources courantes : `document.location`, `window.name`, `innerHTML`.

- **Defense in Depth (Défense en profondeur)** : Stratégie de sécurité consistant à superposer plusieurs couches de protection afin qu'une faille dans une couche soit compensée par les autres.

## E

- **Escape / Échappement** : Transformation des caractères spéciaux pour qu'ils soient traités comme du texte et non comme du code. Essentiel pour prévenir les injections SQL et XSS.

## H

- **Hashing (Hachage)** : Transformation irréversible d'une donnée en une empreinte de taille fixe. Utilisé pour stocker les mots de passe, vérifier l'intégrité des fichiers. Algorithmes : SHA-256, SHA-3, BLAKE3.

- **HSTS (HTTP Strict Transport Security)** : En-tête HTTP ordonnant au navigateur de ne communiquer avec le serveur qu'en HTTPS pendant une durée définie. Prévient les attaques de downgrade SSL/TLS.

- **HMAC (Hash-based Message Authentication Code)** : Code d'authentification de message combinant une fonction de hachage et une clé secrète. Garantit l'intégrité et l'authenticité des données.

## I

- **Injection SQL** : Attaque consistant à insérer du code SQL malveillant dans une requête via des entrées utilisateur non validées. Parade : requêtes paramétrées (prepared statements), ORM, validation des entrées.

## J

- **JWT (JSON Web Token)** : Standard ouvert (RFC 7519) définissant un format compact et autosuffisant pour transmettre des informations de manière sécurisée entre deux parties sous forme de jeton signé (JWS) ou chiffré (JWE).

## K

- **Key Derivation Function (KDF)** : Fonction dérivant une ou plusieurs clés cryptographiques à partir d'un secret (mot de passe, clé maître). Exemples : PBKDF2, scrypt, Argon2.

## L

- **Least Privilege (Moindre privilège)** : Principe selon lequel un utilisateur, un processus ou un programme ne doit disposer que des permissions strictement nécessaires à l'exécution de sa tâche.

## M

- **MFA / 2FA (Multi-Factor Authentication)** : Authentification nécessitant au moins deux facteurs distincts : quelque chose que l'on sait (mot de passe), possède (téléphone) ou est (biométrie).

## N

- **Nonce** : Nombre utilisé une seule fois dans un protocole cryptographique pour prévenir les attaques par rejeu. Utilisé dans CSP (`script-src 'nonce-...'`) et dans les protocoles d'authentification.

## O

- **OAuth2** : Cadre d'autorisation (RFC 6749) permettant à une application tierce d'accéder à des ressources protégées au nom d'un utilisateur, sans partager ses identifiants. Flux : Authorization Code, Client Credentials, PKCE.

- **OIDC (OpenID Connect)** : Couche d'identité construite au-dessus d'OAuth2. Fournit un ID Token (JWT) contenant les informations d'identité de l'utilisateur authentifié.

- **OWASP (Open Worldwide Application Security Project)** : Organisation à but non lucratif publiant des ressources, outils et standards pour améliorer la sécurité des logiciels. Connue pour le OWASP Top 10, l'ASVS et le Testing Guide.

## P

- **Parameterized Query (Requête paramétrée)** : Technique de requête SQL séparant le code SQL des données utilisateur, empêchant les injections SQL. Aussi appelée « prepared statement ».

- **Pentest (Test d'intrusion)** : Évaluation de la sécurité d'un système par simulation d'attaques réelles. Types : boîte noire (aucune info), boîte grise (info partielle), boîte blanche (accès au code source).

## R

- **RBAC (Role-Based Access Control)** : Contrôle d'accès basé sur les rôles. Les permissions sont attribuées à des rôles (`admin`, `editor`, `viewer`) puis les rôles sont assignés aux utilisateurs.

- **Rate Limiting** : Mécanisme limitant le nombre de requêtes qu'un client peut envoyer dans un intervalle de temps donné. Protège contre la force brute, le DDoS et l'abus d'API.

- **Reflected XSS** : Variante de XSS où le code malveillant est renvoyé par le serveur dans sa réponse immédiate (via un paramètre URL non échappé, par exemple).

## S

- **Salt (Sel)** : Valeur aléatoire unique ajoutée à un mot de passe avant le hachage. Empêche les attaques par rainbow tables et garantit que deux mots de passe identiques produisent des hachés différents.

- **Sanitization (Assainissement)** : Nettoyage des entrées utilisateur pour supprimer ou neutraliser le contenu potentiellement dangereux (balises HTML, caractères spéciaux SQL, etc.).

- **SCA (Software Composition Analysis)** : Analyse automatisée des dépendances d'un projet pour identifier les composants open source vulnérables. Outils : `npm audit`, Snyk, Dependabot, Socket.

- **SBOM (Software Bill of Materials)** : Inventaire formel des composants logiciels (dépendances directes et transitives) d'une application. Formats : SPDX, CycloneDX.

- **SSRF (Server-Side Request Forgery)** : Attaque amenant un serveur à effectuer des requêtes HTTP vers des ressources internes ou des services non prévus. Parade : validation des URLs, listes blanches, désactivation des redirections.

- **Stored XSS** : Variante de XSS où le code malveillant est persisté côté serveur (base de données) et exécuté à chaque affichage par les autres utilisateurs.

- **Supply Chain Attack** : Attaque ciblant la chaîne d'approvisionnement logicielle : compromission de paquets npm, typosquatting, injection dans les pipelines CI/CD, ou modification de dépendances transitives.

## T

- **TLS (Transport Layer Security)** : Protocole cryptographique assurant la confidentialité et l'intégrité des communications réseau. Successeur de SSL. Version actuelle : TLS 1.3.

- **Token (Access / Refresh)** : Jeton d'accès (access token) : jeton à courte durée de vie autorisant l'accès aux ressources. Jeton de rafraîchissement (refresh token) : jeton à longue durée de vie permettant d'obtenir un nouveau access token sans re-authentification.

## V

- **Validation des entrées** : Vérification que les données fournies par l'utilisateur respectent le format, le type et les contraintes attendues avant tout traitement. Première ligne de défense contre les injections.

## W

- **WAF (Web Application Firewall)** : Pare-feu applicatif filtrant et surveillant le trafic HTTP entre une application web et Internet. Détecte et bloque les attaques courantes (injection, XSS, etc.). Exemples : Cloudflare WAF, AWS WAF, ModSecurity.

## X

- **X-Content-Type-Options** : En-tête HTTP (`nosniff`) empêchant le navigateur de deviner le type MIME d'une ressource, réduisant les risques d'exécution de contenu malveillant.

- **X-Frame-Options** : En-tête HTTP contrôlant si une page peut être intégrée dans un `<iframe>`. Valeurs : `DENY`, `SAMEORIGIN`. Défense contre le clickjacking.

- **XSS (Cross-Site Scripting)** : Attaque injectant du code JavaScript malveillant dans une page web vue par d'autres utilisateurs. Trois variantes : Reflected, Stored et DOM-based.

## Z

- **Zero-day** : Vulnérabilité inconnue de l'éditeur du logiciel et pour laquelle aucun correctif n'existe. Exploitable dès sa découverte, d'où le nom « jour zéro ».

- **Zero Trust** : Modèle de sécurité fondé sur le principe « ne jamais faire confiance, toujours vérifier ». Chaque requête est authentifiée et autorisée, indépendamment de sa provenance réseau.
