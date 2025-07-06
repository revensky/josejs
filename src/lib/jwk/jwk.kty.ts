/**
 * Supported JSON Web Key Key Types.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1 | JWK "kty" Parameter}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6 | JWK Original Key Types}
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2 | JWK CFRG Key Type}
 */
export type JwkKty = 'EC' | 'OKP' | 'RSA' | 'oct';
