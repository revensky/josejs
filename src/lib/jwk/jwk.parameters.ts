import { JweAlg } from '../jwe/jwe.alg';
import { JweEnc } from '../jwe/jwe.enc';
import { JwsAlg } from '../jws/jws.alg';
import { JwkKeyOp } from './jwk.key-op';
import { JwkKty } from './jwk.kty';
import { JwkUse } from './jwk.use';

/**
 * JSON Web Key Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4 | JWK Parameters}
 */
export interface JwkParameters extends Record<string, unknown> {
  /**
   * Identifies the cryptographic algorithm family used with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.1 | JWK "kty" Parameter}
   */
  readonly kty: JwkKty;

  /**
   * Identifies the intended use of the public key and indicates whether a public key
   * is used for encrypting data or verifying the signature on data.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2 | JWK "use" Parameter}
   */
  use?: JwkUse;

  /**
   * Identifies the operation(s) for which the key is intended to be used.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3 | JWK "key_ops" Parameter}
   */
  key_ops?: JwkKeyOp[];

  /**
   * Identifies the algorithm intended for use with the key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.4 | JWK "alg" Parameter}
   */
  alg?: JweAlg | JweEnc | JwsAlg;

  /**
   * Parameter used to match a specific key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5 | JWK "kid" Parameter}
   */
  kid?: string;

  /**
   * URI that refers to a resource for an X.509 public key certificate or certificate chain.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.6 | JWK "x5u" Parameter}
   */
  x5u?: string;

  /**
   * Contains a chain of one or more PKIX certificates.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.7 | JWK "x5c" Parameter}
   */
  x5c?: string[];

  /**
   * Base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509 certificate.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.8 | JWK "x5t" Parameter}
   */
  x5t?: string;

  /**
   * Base64url-encoded SHA-256 thumbprint of the DER encoding of an X.509 certificate.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.8 | JWK "x5t#S256" Parameter}
   */
  'x5t#S256'?: string;
}
