import { constants } from 'crypto';

import { JwsAlg } from '../../../jws/jws.alg';
import { RSASSAJwsBackend } from './rsassa-jws.backend';

/**
 * Implementation of the PS384 RSASSA-PSS JSON Web Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5 | PS384 JWS Algorithms}
 */
export class PS384JwsBackend extends RSASSAJwsBackend {
  /**
   * Name of the JSON Web Signature Algorithm used by the Backend.
   */
  protected override readonly algorithm: JwsAlg = 'PS384';

  /**
   * Hash algorithm used to sign and verify messages.
   */
  protected readonly hash: 'sha256' | 'sha384' | 'sha512' = 'sha384';

  /**
   * RSA padding used to sign and verify messages.
   */
  protected readonly padding: number = constants.RSA_PKCS1_PSS_PADDING;
}
