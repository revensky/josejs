import { Buffer } from 'buffer';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JwkBackend } from '../jwk.backend';
import { RsaJwkParameters } from './rsa-jwk.parameters';

/**
 * RSA JSON Web Key Backend Implementation.
 */
export class RsaJwkBackend implements JwkBackend {
  /**
   * Validates the provided RSA JSON Web Key Parameters.
   *
   * @param parameters RSA JSON Web Key Parameters.
   */
  public validate(parameters: RsaJwkParameters): void {
    if (parameters.kty !== 'RSA') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "kty".');
    }

    if (typeof parameters.n !== 'string' || Buffer.byteLength(parameters.n, 'base64url') < 256) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "n".');
    }

    if (typeof parameters.e !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "e".');
    }

    if (['d', 'p', 'q', 'dp', 'dq', 'qi'].some((parameter) => typeof parameters[parameter] !== 'undefined')) {
      if (typeof parameters.d !== 'string') {
        throw new InvalidJsonWebKeyException('Invalid json web key parameter "d".');
      }

      if (typeof parameters.p !== 'string') {
        throw new InvalidJsonWebKeyException('Invalid json web key parameter "p".');
      }

      if (typeof parameters.q !== 'string') {
        throw new InvalidJsonWebKeyException('Invalid json web key parameter "q".');
      }

      if (typeof parameters.dp !== 'string') {
        throw new InvalidJsonWebKeyException('Invalid json web key parameter "dp".');
      }

      if (typeof parameters.dq !== 'string') {
        throw new InvalidJsonWebKeyException('Invalid json web key parameter "dq".');
      }

      if (typeof parameters.qi !== 'string') {
        throw new InvalidJsonWebKeyException('Invalid json web key parameter "qi".');
      }
    }
  }
}
