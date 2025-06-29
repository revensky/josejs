import { Buffer } from 'buffer';
import { generateKeyPair } from 'crypto';
import { promisify } from 'util';

import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JsonWebKeyParameters } from '../../../jwk/jsonwebkey.parameters';
import { JsonWebKeyToJSONOptions } from '../../../jwk/jsonwebkey-to-json.options';
import { GenerateRSAJsonWebKeyOptions } from './generate-rsa-jsonwebkey.options';
import { RSAJsonWebKeyParameters } from './rsa.jsonwebkey.parameters';

const generateKeyPairAsync = promisify(generateKeyPair);

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
   * Generates a new RSA JSON Web Key on the fly based on the provided options.
   *
   * @param options Options used to generate the RSA JSON Web Key.
   * @param parameters Optional RSA JSON Web Key Parameters.
   */
  public static async generate(
    options: GenerateRSAJsonWebKeyOptions,
    parameters: Partial<JsonWebKeyParameters> = {},
  ): Promise<RSAJsonWebKey> {
    if (!Number.isInteger(options.modulus)) {
      throw new TypeError('The Modulus must be an integer.');
    }

    if (options.modulus < 2048) {
      throw new TypeError('The Modulus must be at least 2048.');
    }

    if (typeof options.publicExponent !== 'undefined' && !Number.isInteger(options.publicExponent)) {
      throw new TypeError('The Public Exponent must be an integer.');
    }

    const { privateKey } = await generateKeyPairAsync('rsa', {
      modulusLength: options.modulus,
      publicExponent: options.publicExponent ?? 0x010001,
    });

    const privateKeyParameters = <RSAJsonWebKeyParameters>privateKey.export({ format: 'jwk' });

    const rsaJsonWebKeyParameters: RSAJsonWebKeyParameters = Object.assign(
      privateKeyParameters,
      Object.removeNullishValues(parameters),
    );

    return new RSAJsonWebKey(rsaJsonWebKeyParameters);
  }

  /**
   * Returns the parameters of the RSA JSON Web Key in a JSON-friendly format.
   *
   * @param options Options used to customize the returned RSA JSON Web Key Parameters.
   * @returns RSA JSON Web Key Parameters.
   */
  public override toJSON(options?: JsonWebKeyToJSONOptions): RSAJsonWebKeyParameters {
    return <RSAJsonWebKeyParameters>super.toJSON(options);
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

    super.validate(parameters);
  }

  /**
   * Returns the parameters used to calculate the Thumbprint of the
   * RSA JSON Web Key in lexicographic order.
   */
  protected getThumbprintParameters(): RSAJsonWebKeyParameters {
    return { e: this.e, kty: this.kty, n: this.n };
  }

  /**
   * Returns the list of all private parameters of the RSA JSON Web Key.
   */
  protected getPrivateParameters(): string[] {
    return ['d', 'p', 'q', 'dp', 'dq', 'qi'];
  }
}
