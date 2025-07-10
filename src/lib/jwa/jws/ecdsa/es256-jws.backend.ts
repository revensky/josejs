import { JwsAlg } from '../../../jws/jws.alg';
import { JwkCrv } from '../../jwk/jwk.crv';
import { ECDSAJwsBackend } from './ecdsa-jws.backend';

/**
 * Implementation of the ES256 ECDSA JSON Web Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4 | ES256 JWS Algorithm}
 */
export class ES256JwsBackend extends ECDSAJwsBackend {
  /**
   * Name of the JSON Web Signature Algorithm used by the Backend.
   */
  protected override readonly algorithm: JwsAlg = 'ES256';

  /**
   * Hash algorithm used to sign and verify messages.
   */
  protected readonly hash: 'sha256' | 'sha384' | 'sha512' = 'sha256';

  /**
   * Elliptic Curve used by the Backend.
   */
  protected readonly curve: JwkCrv = 'P-256';
}
