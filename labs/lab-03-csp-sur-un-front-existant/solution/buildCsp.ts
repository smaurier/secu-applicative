// buildCsp.ts — SOLUTION DE RÉFÉRENCE (commentée). Ne l'ouvre pas avant ton GREEN.
export function buildCsp(nonce: string): string {
  const directives = [
    `default-src 'self'`,
    `script-src 'self' https://cdn.jsdelivr.net 'nonce-${nonce}'`,
    `style-src 'self'`,
    `img-src 'self' https://images.tribuzen.app`,
    `connect-src 'self' https://api.tribuzen.app`,
    `object-src 'none'`,
    `base-uri 'self'`,
  ];
  return directives.join("; ");
}
