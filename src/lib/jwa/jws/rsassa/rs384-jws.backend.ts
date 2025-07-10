import { constants } from 'crypto';

import { JwsAlg } from '../../../jws/jws.alg';
import { RSASSAJwsBackend } from './rsassa-jws.backend';

/**
 * Implementation of the RS384 RSASSA-PKCS1-v1_5 JSON Web Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3 | RS384 JWS Algorithms}
 */
export class RS384JwsBackend extends RSASSAJwsBackend {
  /**
   * Name of the JSON Web Signature Algorithm used by the Backend.
   */
  protected override readonly algorithm: JwsAlg = 'RS384';

  /**
   * Hash algorithm used to sign and verify messages.
   */
  protected readonly hash: 'sha256' | 'sha384' | 'sha512' = 'sha384';

  /**
   * RSA padding used to sign and verify messages.
   */
  protected readonly padding: number = constants.RSA_PKCS1_PADDING;
}
