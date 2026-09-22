// Oracle du lab 03 sécurité. Ne pas modifier. Parse l'en-tête CSP généré comme un
// navigateur le ferait (directive par directive, source par source) et vérifie deux choses
// à la fois : que RIEN de l'inventaire existant n'est cassé, et que la politique reste
// stricte (pas d'échappatoire `unsafe-*`).
import { describe, expect, it } from "vitest";
import { buildCsp } from "@lab/buildCsp";

function parseCsp(header: string): Record<string, string[]> {
  const directives: Record<string, string[]> = {};
  for (const partie of header.split(";")) {
    const [nom, ...sources] = partie.trim().split(/\s+/);
    if (!nom) continue;
    directives[nom] = sources;
  }
  return directives;
}

describe("buildCsp — ne casse rien de l'inventaire existant du front", () => {
  const csp = parseCsp(buildCsp("abc123"));

  it("script-src autorise 'self' et le CDN tiers existant", () => {
    expect(csp["script-src"]).toContain("'self'");
    expect(csp["script-src"]).toContain("https://cdn.jsdelivr.net");
  });

  it("script-src autorise le script inline de bootstrap via un NONCE (pas unsafe-inline)", () => {
    expect(csp["script-src"]).toContain("'nonce-abc123'");
  });

  it("img-src autorise le host d'images existant", () => {
    expect(csp["img-src"]).toContain("'self'");
    expect(csp["img-src"]).toContain("https://images.tribuzen.app");
  });

  it("connect-src autorise l'API existante", () => {
    expect(csp["connect-src"]).toContain("'self'");
    expect(csp["connect-src"]).toContain("https://api.tribuzen.app");
  });
});

describe("buildCsp — reste STRICTE (aucune échappatoire XSS)", () => {
  it("aucune directive ne contient unsafe-inline ni unsafe-eval", () => {
    const header = buildCsp("abc123");
    expect(header).not.toMatch(/unsafe-inline/);
    expect(header).not.toMatch(/unsafe-eval/);
  });

  it("object-src 'none' et base-uri 'self' sont présents (durcissement indépendant)", () => {
    const csp = parseCsp(buildCsp("abc123"));
    expect(csp["object-src"]).toContain("'none'");
    expect(csp["base-uri"]).toContain("'self'");
  });
});

describe("buildCsp — le nonce est VRAIMENT paramétré (pas une valeur figée)", () => {
  it("deux appels avec des nonces différents produisent des en-têtes différents", () => {
    const header1 = buildCsp("nonce-un");
    const header2 = buildCsp("nonce-deux");
    expect(header1).not.toBe(header2);
    expect(header1).toContain("'nonce-nonce-un'");
    expect(header2).toContain("'nonce-nonce-deux'");
  });
});
