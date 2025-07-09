import { JwkParameters } from '../jwk/jwk.parameters';
import { JwsAlg } from './jws.alg';

/**
 * JSON Web Signature Header Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4 | JWS Header}
 */
export interface JwsHeader extends Record<string, unknown> {
  /**
   * Identifies the cryptographic algorithm used to secure the JWS.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1 | JWS Algorithm Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1 | JWS Algorithms}
   */
  readonly alg: JwsAlg;

  /**
   * URI that refers to a resource for a set of JSON-encoded public keys, one of which
   * corresponds to the key used to digitally sign the JWS.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.2 | JWS JWK Set URL Header Parameter}
   */
  jku?: string;

  /**
   * Public key that corresponds to the key used to digitally sign the JWS.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.3 | JWS JSON Web Key Header Parameter}
   */
  jwk?: JwkParameters;

  /**
   * Hint indicating which key was used to secure the JWS.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4 | JWS Key ID Header Parameter}
   */
  kid?: string;

  /**
   * URI that refers to a resource for the X.509 public key certificate or certificate chain
   * corresponding to the key used to digitally sign the JWS.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.5 | JWS X.509 URL Header Parameter}
   */
  x5u?: string;

  /**
   * X.509 public key certificate or certificate chain corresponding to the key
   * used to digitally sign the JWS.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6 | JWS X.509 Certificate Chain Header Parameter}
   */
  x5c?: string[];

  /**
   * Base64url-encoded SHA-1 thumbprint of the DER encoding of the X.509 certificate
   * corresponding to the key used to digitally sign the JWS.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.7 | JWS X.509 Certificate SHA-1 Thumbprint Header Parameter}
   */
  x5t?: string;

  /**
   * Base64url-encoded SHA-256 thumbprint of the DER encoding of the X.509 certificate
   * corresponding to the key used to digitally sign the JWS.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8 | JWS X.509 Certificate SHA-256 Thumbprint Header Parameter}
   */
  'x5t#S256'?: string;

  /**
   * Declares the media type of the complete JWS or JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9 | JWS Type Header Parameter}
   */
  typ?: string;

  /**
   * Declares the media type of the secured content of the JWS or JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10 | JWS Content Type Header Parameter}
   */
  cty?: string;

  /**
   * Defines the extension parameters that must be present in the JOSE Header.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11 | JWS Critical Header Parameter}
   */
  crit?: string[];
}
