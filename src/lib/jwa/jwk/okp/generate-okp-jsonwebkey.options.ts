import { JwkCrv } from '../ec/jwk-crv.type';

/**
 * Octet Key Pair JSON Web Key Generation Options.
 */
export interface GenerateOKPJsonWebKeyOptions extends Record<string, unknown> {
  /**
   * Name of the Elliptic Curve.
   */
  readonly curve: Extract<JwkCrv, 'Ed25519' | 'Ed448' | 'X25519' | 'X448'>;
}
