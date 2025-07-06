import { JwkParameters } from '../../../jwk/jwk.parameters';

/**
 * RSA JSON Web Key Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3 | RSA JWK Parameters}
 */
export interface RsaJwkParameters extends JwkParameters {
  /**
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3 | RSA JWK "kty" Parameter}
   */
  readonly kty: 'RSA';

  /**
   * Contains the modulus value for the RSA public key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1.1 | RSA JWK "n" Parameter}
   */
  readonly n: string;

  /**
   * Contains the exponent value for the RSA public key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1.2 | RSA JWK "e" Parameter}
   */
  readonly e: string;

  /**
   * Contains the private exponent value for the RSA private key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.1 | RSA JWK "d" Parameter}
   */
  readonly d?: string;

  /**
   * Contains the first prime factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.2 | RSA JWK "p" Parameter}
   */
  readonly p?: string;

  /**
   * Contains the second prime factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.3 | RSA JWK "q" Parameter}
   */
  readonly q?: string;

  /**
   * Contains the Chinese Remainder Theorem (CRT) exponent of the first factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.4 | RSA JWK "dp" Parameter}
   */
  readonly dp?: string;

  /**
   * Contains the Chinese Remainder Theorem (CRT) exponent of the second factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.5 | RSA JWK "dq" Parameter}
   */
  readonly dq?: string;

  /**
   * Contains the Chinese Remainder Theorem (CRT) coefficient of the second factor.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2.6 | RSA JWK "qi" Parameter}
   */
  readonly qi?: string;
}
