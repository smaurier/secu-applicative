// UserAccountService.ts — SOLUTION DE RÉFÉRENCE (commentée). Ne l'ouvre pas avant ton GREEN.
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

export class RegistrationError extends Error {}

const MAX_FAILED_ATTEMPTS = 5;
const COMMON_WEAK_PASSWORDS = new Set(["password", "123456", "azerty", "motdepasse", "letmein"]);

interface UserRecord {
  salt: string;
  passwordHash: string;
  failedAttempts: number;
  locked: boolean;
}

function hashWithSalt(password: string, salt: string): string {
  // scrypt : dérivation LENTE et coûteuse en mémoire, à l'opposé d'un sha256 simple —
  // c'est justement sa lenteur qui rend une attaque par force brute hors ligne coûteuse.
  return scryptSync(password, salt, 64).toString("hex");
}

export class UserAccountService {
  private readonly users = new Map<string, UserRecord>();

  register(username: string, password: string): void {
    // A04 — politique de mot de passe minimale : longueur ET pas un classique du top des
    // mots de passe les plus utilisés (une longueur seule n'empêche pas "aaaaaaaa").
    if (password.length < 10) {
      throw new RegistrationError("Le mot de passe doit faire au moins 10 caractères.");
    }
    if (COMMON_WEAK_PASSWORDS.has(password.toLowerCase())) {
      throw new RegistrationError("Ce mot de passe est trop commun.");
    }

    // A02 — un sel ALÉATOIRE par utilisateur : deux comptes avec le même mot de passe
    // n'auront jamais le même hash, une table arc-en-ciel précalculée devient inutile.
    const salt = randomBytes(16).toString("hex");
    const passwordHash = hashWithSalt(password, salt);
    this.users.set(username, { salt, passwordHash, failedAttempts: 0, locked: false });
  }

  login(username: string, password: string): boolean {
    const user = this.users.get(username);
    if (!user || user.locked) return false;

    const hash = hashWithSalt(password, user.salt);
    const bufA = Buffer.from(hash, "hex");
    const bufB = Buffer.from(user.passwordHash, "hex");
    const valide = bufA.length === bufB.length && timingSafeEqual(bufA, bufB);

    if (valide) {
      user.failedAttempts = 0;
      return true;
    }

    // A07 — verrouillage après N échecs : sans ça, rien n'empêche un attaquant de tester
    // des milliers de mots de passe par seconde contre un seul compte.
    user.failedAttempts += 1;
    if (user.failedAttempts >= MAX_FAILED_ATTEMPTS) user.locked = true;
    return false;
  }
}
