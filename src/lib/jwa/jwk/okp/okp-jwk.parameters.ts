import { JwkParameters } from '../../../jwk/jwk.parameters';
import { JwkCrv } from '../jwk.crv';

/**
 * Octet Key Pair JSON Web Key Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2 | OKP JWK Parameters}
 */
export interface OkpJwkParameters extends JwkParameters {
  /**
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2 | OKP JWK "kty" Parameter}
   */
  readonly kty: 'OKP';

  /**
   * Identifies the cryptographic curve used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-3 | OKP JWK "crv" Parameter}
   */
  readonly crv: Extract<JwkCrv, 'Ed25519' | 'Ed448' | 'X25519' | 'X448'>;

  /**
   * Contains the x coordinate for the Elliptic Curve point.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2 | OKP JWK "x" Parameter}
   */
  readonly x: string;

  /**
   * Contains the Elliptic Curve private key value.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2 | OKP JWK "d" Parameter}
   */
  readonly d?: string;
}
