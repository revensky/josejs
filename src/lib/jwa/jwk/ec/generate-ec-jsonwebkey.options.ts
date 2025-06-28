import { JwkCrv } from './jwk-crv.type';

/**
 * Elliptic Curve JSON Web Key Generation Options.
 */
export interface GenerateECJsonWebKeyOptions extends Record<string, unknown> {
  /**
   * Name of the Elliptic Curve.
   */
  readonly curve: Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>;
}
