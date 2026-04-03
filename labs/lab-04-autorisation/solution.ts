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
// Implémentations
// ============================================================================

function createRBACSystem(roleDefs: RoleDefinition[]): RBACSystem {
  const roleMap = new Map<string, RoleDefinition>();
  for (const role of roleDefs) {
    roleMap.set(role.name, role);
  }

  function resolvePermissions(roleName: string, visited: Set<string> = new Set()): Permission[] {
    if (visited.has(roleName)) return [];
    visited.add(roleName);

    const role = roleMap.get(roleName);
    if (!role) return [];

    const perms = [...role.permissions];
    if (role.inherits) {
      for (const parent of role.inherits) {
        perms.push(...resolvePermissions(parent, visited));
      }
    }
    return perms;
  }

  return {
    hasPermission(user: User, resource: string, action: string): boolean {
      const perms = this.getUserPermissions(user);
      return perms.some((p) => p.resource === resource && p.action === action);
    },

    getUserPermissions(user: User): Permission[] {
      const allPerms: Permission[] = [];
      for (const roleName of user.roles) {
        allPerms.push(...resolvePermissions(roleName));
      }
      // Dédupliquer
      const seen = new Set<string>();
      return allPerms.filter((p) => {
        const key = `${p.resource}:${p.action}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    },
  };
}

function checkIDOR(requestUserId: string, resourceOwnerId: string, userRoles: string[]): boolean {
  if (requestUserId === resourceOwnerId) return true;
  if (userRoles.includes('admin')) return true;
  return false;
}

function createRateLimiter(maxRequests: number, windowMs: number): RateLimiter {
  const requests = new Map<string, number[]>();

  function getValidRequests(userId: string, now: number): number[] {
    const userRequests = requests.get(userId) ?? [];
    return userRequests.filter((t) => now - t < windowMs);
  }

  return {
    isAllowed(userId: string, now?: number): boolean {
      const currentTime = now ?? Date.now();
      const valid = getValidRequests(userId, currentTime);

      if (valid.length >= maxRequests) {
        requests.set(userId, valid);
        return false;
      }

      valid.push(currentTime);
      requests.set(userId, valid);
      return true;
    },

    getRemainingRequests(userId: string, now?: number): number {
      const currentTime = now ?? Date.now();
      const valid = getValidRequests(userId, currentTime);
      return Math.max(0, maxRequests - valid.length);
    },
  };
}

function filterSensitiveFields(
  data: Record<string, any>,
  role: string,
  fieldConfig: Record<string, string[]>
): Record<string, any> {
  const allowedFields = fieldConfig[role];
  if (!allowedFields) return {};

  const result: Record<string, any> = {};
  for (const field of allowedFields) {
    if (field in data) {
      result[field] = data[field];
    }
  }
  return result;
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
