/**
 * Supported JSON Web Key Elliptic Curves.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1 | JWK NIST Elliptic Curves}
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3 | JWK CRFG Elliptic Curves}
 */
export type JwkCrv = 'Ed25519' | 'Ed448' | 'P-256' | 'P-384' | 'P-521' | 'X25519' | 'X448';
