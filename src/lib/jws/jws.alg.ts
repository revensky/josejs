/**
 * Supported JSON Web Signature Algorithms.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1 | JWS "alg" Parameter}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3 | JWS Algorithms}
 */
export type JwsAlg =
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'HS256'
  | 'HS384'
  | 'HS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'none';
