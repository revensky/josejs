import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JwkBackend } from '../jwk.backend';
import { JwkCrv } from '../jwk.crv';
import { EcJwkParameters } from './ec-jwk.parameters';

/**
 * Elliptic Curve JSON Web Key Backend Implementation.
 */
export class EcJwkBackend implements JwkBackend {
  /**
   * Elliptic Curves supported by the Elliptic Curve JSON Web Key Backend.
   */
  private readonly supportedCurves: Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>[] = ['P-256', 'P-384', 'P-521'];

  /**
   * Validates the provided Elliptic Curve JSON Web Key Parameters.
   *
   * @param parameters Elliptic Curve JSON Web Key Parameters.
   */
  public validate(parameters: EcJwkParameters): void {
    if (parameters.kty !== 'EC') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "kty".');
    }

    if (typeof parameters.crv !== 'string' || !this.supportedCurves.includes(parameters.crv)) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "crv".');
    }

    if (typeof parameters.x !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x".');
    }

    if (typeof parameters.y !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "y".');
    }

    if (typeof parameters.d !== 'undefined' && typeof parameters.d !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "d".');
    }
  }
}
