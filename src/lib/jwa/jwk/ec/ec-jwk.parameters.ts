import { JwkParameters } from '../../../jwk/jwk.parameters';
import { JwkCrv } from '../jwk.crv';

/**
 * Elliptic Curve JSON Web Key Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2 | EC JWK Parameters}
 */
export interface EcJwkParameters extends JwkParameters {
  /**
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2 | EC JWK "kty" Parameter}
   */
  readonly kty: 'EC';

  /**
   * Identifies the cryptographic curve used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1 | EC JWK "crv" Parameter}
   */
  readonly crv: Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>;

  /**
   * Contains the x coordinate for the Elliptic Curve point.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.2 | EC JWK "x" Parameter}
   */
  readonly x: string;

  /**
   * Contains the y coordinate for the Elliptic Curve point.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.3 | EC JWK "y" Parameter}
   */
  readonly y: string;

  /**
   * Contains the Elliptic Curve private key value.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.2.1 | EC JWK "d" Parameter}
   */
  readonly d?: string;
}
