import { createTestRunner } from '../test-utils.js';
const { test, assert, assertEqual, assertDeepEqual, summary } = createTestRunner('Lab 04 — Autorisation');

// ============================================================================
// Types
// ============================================================================

interface User {
  id: string;
  username: string;
  roles: string[];
  attributes?: Record<string, any>;
}

interface Permission {
  resource: string;
  action: 'read' | 'write' | 'delete' | 'admin';
}

interface RoleDefinition {
  name: string;
  permissions: Permission[];
  inherits?: string[];
}

interface RBACSystem {
  hasPermission: (user: User, resource: string, action: string) => boolean;
  getUserPermissions: (user: User) => Permission[];
}

interface RateLimiter {
  isAllowed: (userId: string, now?: number) => boolean;
  getRemainingRequests: (userId: string, now?: number) => number;
}

// ============================================================================
// Fonctions à implémenter
// ============================================================================

/**
 * Crée un système RBAC avec support de l'héritage de rôles.
 * - hasPermission : vérifie si un utilisateur a une permission (resource + action)
 * - getUserPermissions : retourne toutes les permissions d'un utilisateur (incluant l'héritage)
 * L'héritage doit être résolu récursivement.
 */
function createRBACSystem(roles: RoleDefinition[]): RBACSystem {
  // TODO: Implémenter le système RBAC
  return {
    hasPermission: (_user, _resource, _action) => false,
    getUserPermissions: (_user) => [],
  };
}

/**
 * Vérifie si l'accès est autorisé (protection IDOR).
 * L'accès est autorisé si :
 * - requestUserId === resourceOwnerId (l'utilisateur accède à sa propre ressource)
 * - OU l'utilisateur a le rôle 'admin'
 */
function checkIDOR(requestUserId: string, resourceOwnerId: string, userRoles: string[]): boolean {
  // TODO: Vérifier l'accès IDOR
  return false;
}

/**
 * Crée un limiteur de débit à fenêtre glissante.
 * - maxRequests : nombre maximum de requêtes dans la fenêtre
 * - windowMs : durée de la fenêtre en millisecondes
 * - isAllowed : retourne true si la requête est autorisée
 * - getRemainingRequests : retourne le nombre de requêtes restantes
 */
function createRateLimiter(maxRequests: number, windowMs: number): RateLimiter {
  // TODO: Implémenter le rate limiter
  return {
    isAllowed: (_userId, _now?) => true,
    getRemainingRequests: (_userId, _now?) => 0,
  };
}

/**
 * Filtre les champs sensibles d'un objet selon le rôle de l'utilisateur.
 * fieldConfig mappe chaque rôle vers la liste des champs autorisés.
 * Si le rôle n'est pas dans la config, retourne un objet vide.
 */
function filterSensitiveFields(
  data: Record<string, any>,
  role: string,
  fieldConfig: Record<string, string[]>
): Record<string, any> {
  // TODO: Filtrer les champs selon le rôle
  return {};
}

// ============================================================================
// Tests
// ============================================================================

const roles: RoleDefinition[] = [
  { name: 'viewer', permissions: [{ resource: 'articles', action: 'read' }] },
  { name: 'editor', permissions: [{ resource: 'articles', action: 'write' }], inherits: ['viewer'] },
  { name: 'admin', permissions: [{ resource: 'articles', action: 'delete' }, { resource: 'users', action: 'admin' }], inherits: ['editor'] },
];

await test('RBAC — permissions directes', async () => {
  const rbac = createRBACSystem(roles);
  const viewer: User = { id: '1', username: 'alice', roles: ['viewer'] };
  assert(rbac.hasPermission(viewer, 'articles', 'read'), 'Viewer peut lire les articles');
  assert(!rbac.hasPermission(viewer, 'articles', 'write'), 'Viewer ne peut pas écrire');
});

await test('RBAC — héritage de rôles', async () => {
  const rbac = createRBACSystem(roles);
  const editor: User = { id: '2', username: 'bob', roles: ['editor'] };
  assert(rbac.hasPermission(editor, 'articles', 'read'), 'Editor hérite de read via viewer');
  assert(rbac.hasPermission(editor, 'articles', 'write'), 'Editor peut écrire');
  assert(!rbac.hasPermission(editor, 'articles', 'delete'), 'Editor ne peut pas supprimer');
});

await test('RBAC — getUserPermissions inclut l\'héritage', async () => {
  const rbac = createRBACSystem(roles);
  const admin: User = { id: '3', username: 'charlie', roles: ['admin'] };
  const perms = rbac.getUserPermissions(admin);
  assert(perms.length >= 4, 'Admin devrait avoir au moins 4 permissions');
});

await test('checkIDOR — propriétaire autorisé', async () => {
  assert(checkIDOR('user1', 'user1', ['viewer']), 'Propriétaire peut accéder');
  assert(!checkIDOR('user1', 'user2', ['viewer']), 'Non-propriétaire non-admin ne peut pas accéder');
});

await test('checkIDOR — admin autorisé sur toute ressource', async () => {
  assert(checkIDOR('user1', 'user2', ['admin']), 'Admin peut accéder à toute ressource');
});

await test('rateLimiter — autorise dans la limite', async () => {
  const limiter = createRateLimiter(3, 1000);
  assert(limiter.isAllowed('user1', 0), 'Première requête autorisée');
  assert(limiter.isAllowed('user1', 100), 'Deuxième requête autorisée');
  assert(limiter.isAllowed('user1', 200), 'Troisième requête autorisée');
  assert(!limiter.isAllowed('user1', 300), 'Quatrième requête refusée');
});

await test('rateLimiter — réinitialise après la fenêtre', async () => {
  const limiter = createRateLimiter(2, 1000);
  limiter.isAllowed('user1', 0);
  limiter.isAllowed('user1', 100);
  assert(!limiter.isAllowed('user1', 200), 'Limite atteinte');
  assert(limiter.isAllowed('user1', 1100), 'Autorisé après expiration de la fenêtre');
  assertEqual(limiter.getRemainingRequests('user1', 1100), 1);
});

await test('filterSensitiveFields — filtre selon le rôle', async () => {
  const data = { id: '1', name: 'Alice', email: 'alice@test.com', salary: 50000, ssn: '123-45-6789' };
  const config = {
    public: ['id', 'name'],
    hr: ['id', 'name', 'email', 'salary', 'ssn'],
  };
  assertDeepEqual(filterSensitiveFields(data, 'public', config), { id: '1', name: 'Alice' });
  assertDeepEqual(filterSensitiveFields(data, 'unknown', config), {});
  assert(Object.keys(filterSensitiveFields(data, 'hr', config)).length === 5, 'HR voit tous les champs');
});

summary();
