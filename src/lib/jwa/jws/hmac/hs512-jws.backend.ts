import { JwsAlg } from '../../../jws/jws.alg';
import { HMACJwsBackend } from './hmac-jws.backend';

/**
 * Implementation of the HS512 HMAC JSON Web Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2 | HMAC JWS Algorithm}
 */
export class HS512JwsBackend extends HMACJwsBackend {
  /**
   * Name of the JSON Web Signature Algorithm used by the Backend.
   */
  protected override readonly algorithm: JwsAlg = 'HS512';

  /**
   * Hash algorithm used to sign and verify messages.
   */
  protected readonly hash: 'sha256' | 'sha384' | 'sha512' = 'sha512';

  /**
   * Size of the secret accepted by the Backend.
   */
  protected readonly keySize: number = 64;
}
