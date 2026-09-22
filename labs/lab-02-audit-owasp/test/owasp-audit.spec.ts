// Oracle de l'AUDIT. Ne pas modifier. Trois failles réelles, chacune prouvée par une
// attaque simulée — jamais par une simple lecture du code.
import { describe, expect, it } from "vitest";
import { RegistrationError, UserAccountService } from "@lab/UserAccountService";

// Accès à l'état interne à des fins de PREUVE uniquement (le `private` TypeScript n'existe
// qu'à la compilation — au runtime, la propriété est bien là). Le but n'est pas de tester un
// détail d'implémentation au hasard, c'est de vérifier LA propriété de sécurité elle-même
// (deux mots de passe identiques ne doivent jamais produire le même hash stocké).
function hashStocke(service: UserAccountService, username: string): string {
  return (service as unknown as { users: Map<string, { passwordHash: string }> }).users.get(username)!
    .passwordHash;
}

describe("A02:2021 Cryptographic Failures — le hachage doit être salé", () => {
  it("deux comptes avec le MÊME mot de passe ont des hash stockés DIFFÉRENTS", () => {
    const service = new UserAccountService();
    service.register("alice", "SuperSecret2026!");
    service.register("bob", "SuperSecret2026!");

    expect(hashStocke(service, "alice")).not.toBe(hashStocke(service, "bob"));
  });

  it("le mot de passe reste vérifiable malgré le sel (login fonctionne toujours)", () => {
    const service = new UserAccountService();
    service.register("alice", "SuperSecret2026!");
    expect(service.login("alice", "SuperSecret2026!")).toBe(true);
  });
});

describe("A04:2021 Insecure Design — politique de mot de passe minimale", () => {
  it("refuse un mot de passe manifestement trop court", () => {
    const service = new UserAccountService();
    expect(() => service.register("alice", "a1")).toThrow(RegistrationError);
  });

  it("refuse un mot de passe parmi les plus utilisés au monde", () => {
    const service = new UserAccountService();
    expect(() => service.register("alice", "password")).toThrow(RegistrationError);
  });

  it("accepte un mot de passe raisonnable", () => {
    const service = new UserAccountService();
    expect(() => service.register("alice", "Ch3valBleuDansLePre!")).not.toThrow();
  });
});

describe("A07:2021 Identification and Authentication Failures — résistance au brute force", () => {
  it("verrouille le compte après plusieurs échecs de connexion, même avec le BON mot de passe ensuite", () => {
    const service = new UserAccountService();
    service.register("alice", "SuperSecret2026!");

    for (let i = 0; i < 5; i++) {
      service.login("alice", "mauvais-mot-de-passe");
    }

    // Un script qui teste des milliers de mots de passe au hasard doit être stoppé BIEN
    // avant de tomber par chance sur le bon — ici même le bon mot de passe échoue ensuite.
    expect(service.login("alice", "SuperSecret2026!")).toBe(false);
  });

  it("un utilisateur légitime (peu d'échecs) reste connectable normalement", () => {
    const service = new UserAccountService();
    service.register("alice", "SuperSecret2026!");
    service.login("alice", "faute-de-frappe");
    expect(service.login("alice", "SuperSecret2026!")).toBe(true);
  });
});
