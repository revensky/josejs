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

  /**
   * Returns the Public Octet Sequence JSON Web Key Parameters in lexical order to calculate the Thumbprint.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7638.html#section-3.2 | oct JWK Thumbprint}
   *
   * @param parameters Octet Sequence JSON Web Key Parameters.
   * @returns Public Octet Sequence JSON Web Key Parameters for Thumbprint.
   */
  public getThumbprintParameters(parameters: OctJwkParameters): OctJwkParameters {
    return { k: parameters.k, kty: parameters.kty };
  }

  /**
   * Returns a list with the private parameters of the Octet Sequence JSON Web Key.
   *
   * @returns Octet Sequence JSON Web Key Private Parameters.
   */
  public getPrivateParameters(): string[] {
    return [];
  }
}
