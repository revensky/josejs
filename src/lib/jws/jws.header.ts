import { JoseHeader } from '../jose/jose.header';
import { JwsAlg } from './jws.alg';

/**
 * JSON Web Signature Header Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4 | JWS Header}
 */
export interface JwsHeader extends JoseHeader {
  /**
   * Identifies the cryptographic algorithm used to secure the JWS.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1 | JWS Algorithm Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1 | JWS Algorithms}
   */
  readonly alg: JwsAlg;
}
