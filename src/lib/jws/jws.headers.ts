import { JwsHeader } from './jws.header';

/**
 * JSON Web Signature JSON Serialization Multiple Headers Implementation.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1 | JWS Signatures}
 */
export interface JwsHeaders {
  /**
   * JSON Web Signature JWS Protected JOSE Header.
   */
  readonly protectedHeader?: JwsHeader;

  /**
   * JSON Web Signature JWS Unprotected JOSE Header.
   */
  readonly unprotectedHeader?: JwsHeader;
}
