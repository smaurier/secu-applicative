// UserAccountService.ts — L'EXISTANT, EN PRODUCTION. Ticket d'audit : « avant qu'on ouvre
// l'inscription au public, un audit de sécurité rapide sur ce module — trouve et corrige le
// top 3, classé OWASP Top 10 2021. » Ce fichier COMPILE et MARCHE : la démo passe,
// inscription et connexion fonctionnent. Les trois failles sont réelles mais invisibles à
// l'usage normal.
//
// AVANT de modifier quoi que ce soit : remplis `AUDIT.md` à la racine du lab.
//
// Les trois failles à trouver et corriger (voir AUDIT.md pour le protocole, test/*.spec.ts
// pour la preuve exacte attendue de chacune) :
//   1. A02:2021 Cryptographic Failures — le hachage des mots de passe.
//   2. A04:2021 Insecure Design — la politique de mot de passe (ou son absence).
//   3. A07:2021 Identification and Authentication Failures — la résistance au brute force.
//
// Contrat public à CONSERVER (les signatures ne changent pas) :
//   register(username: string, password: string): void — lève RegistrationError si le mot
//     de passe est jugé trop faible (à toi de définir la politique, voir AUDIT.md).
//   login(username: string, password: string): boolean — false si mot de passe faux OU
//     compte verrouillé (pas de distinction observable entre les deux, volontairement — un
//     attaquant ne doit pas apprendre "ce compte existe et est juste verrouillé").
import { createHash } from "node:crypto";

export class RegistrationError extends Error {}

interface UserRecord {
  passwordHash: string;
}

export class UserAccountService {
  private readonly users = new Map<string, UserRecord>();

  register(username: string, password: string): void {
    const passwordHash = createHash("sha256").update(password).digest("hex");
    this.users.set(username, { passwordHash });
  }

  login(username: string, password: string): boolean {
    const user = this.users.get(username);
    if (!user) return false;
    const hash = createHash("sha256").update(password).digest("hex");
    return hash === user.passwordHash;
  }
}
