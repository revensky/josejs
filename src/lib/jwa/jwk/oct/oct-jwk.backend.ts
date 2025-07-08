import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JwkBackend } from '../jwk.backend';
import { OctJwkParameters } from './oct-jwk.parameters';

/**
 * Octet Sequence JSON Web Key Backend Implementation.
 */
export class OctJwkBackend implements JwkBackend {
  /**
   * Validates the provided Octet Sequence JSON Web Key Parameters.
   *
   * @param parameters Octet Sequence JSON Web Key Parameters.
   */
  public validate(parameters: OctJwkParameters): void {
    if (parameters.kty !== 'oct') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "kty".');
    }

    if (typeof parameters.k !== 'string' || parameters.k.length === 0) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "k".');
    }
  }
}
