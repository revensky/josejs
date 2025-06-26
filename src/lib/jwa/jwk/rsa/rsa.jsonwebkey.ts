import { Buffer } from 'buffer';

import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { RSAJsonWebKeyParameters } from './rsa.jsonwebkey.parameters';

/**
 * RSA JSON Web Key Implementation.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3 | RSA JWK}
 */
export class RSAJsonWebKey extends JsonWebKey {
  /**
   * JSON Web Key Type.
   */
  public readonly kty!: 'RSA';

  /**
   * Modulus.
   */
  public readonly n!: string;

  /**
   * Public Exponent.
   */
  public readonly e!: string;

  /**
   * Private Exponent.
   */
  public readonly d?: string;

  /**
   * First Prime Factor.
   */
  public readonly p?: string;

  /**
   * Second Prime Factor.
   */
  public readonly q?: string;

  /**
   * First Factor CRT Exponent.
   */
  public readonly dp?: string;

  /**
   * Second Factor CRT Exponent.
   */
  public readonly dq?: string;

  /**
   * First Factor CRT Coefficient.
   */
  public readonly qi?: string;

  /**
   * Instantiates a new RSA JSON Web Key based on the provided Parameters.
   *
   * @param parameters RSA JSON Web Key Parameters.
   */
  public constructor(parameters: RSAJsonWebKey | RSAJsonWebKeyParameters) {
    super(parameters);
    Object.assign(this, Object.removeNullishValues(parameters));
  }

  /**
   * Returns the parameters of the RSA JSON Web Key in a JSON-friendly format.
   *
   * @returns RSA JSON Web Key Parameters.
   */
  public override toJSON(): RSAJsonWebKeyParameters {
    return super.toJSON() as RSAJsonWebKeyParameters;
  }

  /**
   * Validates the provided RSA JSON Web Key Parameters.
   *
   * @param parameters Parameters of the RSA JSON Web Key.
   */
  protected override validate(parameters: RSAJsonWebKeyParameters): void {
    if (parameters.kty !== 'RSA') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "kty".');
    }

    if (typeof parameters.n !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "n".');
    }

    if (Buffer.byteLength(parameters.n, 'base64url') < 256) {
      throw new InvalidJsonWebKeyException('The RSA Modulus must be at least 2048.');
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

    super.validate(parameters);
  }

  /**
   * Returns the parameters used to calculate the Thumbprint of the
   * RSA JSON Web Key in lexicographic order.
   */
  protected getThumbprintParameters(): RSAJsonWebKeyParameters {
    return { e: this.e, kty: this.kty, n: this.n };
  }
}
