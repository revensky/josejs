import { JwkParameters } from '../../../jwk/jwk.parameters';

/**
 * Octet Sequence JSON Web Key Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4 | oct JWK Parameters}
 */
export interface OctJwkParameters extends JwkParameters {
  /**
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4 | oct JWK "kty" Parameter}
   */
  readonly kty: 'oct';

  /**
   * Contains the value of the symmetric (or other single-valued) key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4.1 | oct JWK "k" Parameter}
   */
  readonly k: string;
}
