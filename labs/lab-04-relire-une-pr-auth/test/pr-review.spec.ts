// Oracle de la REVUE. Ne pas modifier. RED sur les deux problèmes réels de la PR, GREEN une
// fois corrigés. Le second n'est pas mesurable de façon fiable par le timing (trop instable
// en CI) — la preuve est une relecture du code source, honnêtement documentée comme telle
// (même limite que jest-axe dans le lab 04 du cours Design System : un test automatisé ne
// prouve que ce qu'il peut mesurer).
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { signSession, verifySession } from "@lab/SessionToken";

describe("SessionToken — un token EXPIRÉ doit être rejeté (Session Management, A07)", () => {
  it("un token dont expiresAt est dans le passé est rejeté, même avec une signature valide", () => {
    const tokenExpire = signSession("user-42", Date.now() - 1000);
    expect(verifySession(tokenExpire)).toBeNull();
  });

  it("un token dont expiresAt est dans le futur reste accepté", () => {
    const tokenValide = signSession("user-42", Date.now() + 60_000);
    expect(verifySession(tokenValide)).toBe("user-42");
  });
});

describe("SessionToken — comparaison de signature à temps constant (A02, relecture du source)", () => {
  it("utilise timingSafeEqual (node:crypto), pas une comparaison de chaînes directe", () => {
    const rawSource = readFileSync(process.env.LAB_ROOT + "/SessionToken.ts", "utf8");
    const source = rawSource
      .split("\n")
      .filter((l) => !l.trim().startsWith("//"))
      .join("\n");

    expect(source).toMatch(/timingSafeEqual/);
    expect(source).not.toMatch(/sig\s*!==\s*expectedSig/);
  });
});
