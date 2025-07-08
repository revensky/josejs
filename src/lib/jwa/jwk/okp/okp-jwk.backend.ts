import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JwkBackend } from '../jwk.backend';
import { JwkCrv } from '../jwk.crv';
import { OkpJwkParameters } from './okp-jwk.parameters';

/**
 * Octet Key Pair JSON Web Key Backend Implementation.
 */
export class OkpJwkBackend implements JwkBackend {
  /**
   * Elliptic Curves supported by the Octet Key Pair JSON Web Key Backend.
   */
  private readonly supportedCurves: Extract<JwkCrv, 'Ed25519' | 'Ed448' | 'X25519' | 'X448'>[] = [
    'Ed25519',
    'Ed448',
    'X25519',
    'X448',
  ];

  /**
   * Validates the provided Octet Key Pair JSON Web Key Parameters.
   *
   * @param parameters Octet Key Pair JSON Web Key Parameters.
   */
  public validate(parameters: OkpJwkParameters): void {
    if (parameters.kty !== 'OKP') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "kty".');
    }

    if (typeof parameters.crv !== 'string' || !this.supportedCurves.includes(parameters.crv)) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "crv".');
    }

    if (typeof parameters.x !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x".');
    }

    if (typeof parameters.d !== 'undefined' && typeof parameters.d !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "d".');
    }
  }
}
