/**
 * Supported JSON Web Key Key Operations.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3 | JWK Key Operations}
 */
export type JwkKeyOp = 'decrypt' | 'deriveBits' | 'deriveKey' | 'encrypt' | 'sign' | 'unwrapKey' | 'verify' | 'wrapKey';
