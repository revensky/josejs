import { JwkParameters } from '../jwk/jwk.parameters';

/**
 * JSON Web Key Set Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5 | JWKS Parameters}
 */
export interface JwksParameters extends Record<string, unknown> {
  /**
   * JSON Web Keys registered at the JSON Web Key Set.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-5.1 | JWKS "keys" Parameter}
   */
  readonly keys: JwkParameters[];
}
