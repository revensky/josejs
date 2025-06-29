import { Buffer } from 'buffer';
import { randomBytes } from 'crypto';
import { promisify } from 'util';

import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JsonWebKeyParameters } from '../../../jwk/jsonwebkey.parameters';
import { JsonWebKeyToJSONOptions } from '../../../jwk/jsonwebkey-to-json.options';
import { GenerateOCTJsonWebKeyOptions } from './generate-oct-jsonwebkey.options';
import { OCTJsonWebKeyParameters } from './oct.jsonwebkey.parameters';

const randomBytesAsync = promisify(randomBytes);

/**
 * Octet Sequence JSON Web Key Implementation.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4 | OCT JWK}
 */
export class OCTJsonWebKey extends JsonWebKey {
  /**
   * JSON Web Key Type.
   */
  public readonly kty!: 'oct';

  /**
   * Base64Url encoded Octet Sequence Secret.
   */
  public readonly k!: string;

  /**
   * Instantiates a new Octet Sequence JSON Web Key based on the provided Parameters.
   *
   * @param parameters Octet Sequence JSON Web Key Parameters.
   */
  public constructor(parameters: OCTJsonWebKey | OCTJsonWebKeyParameters) {
    super(parameters);
    Object.assign(this, Object.removeNullishValues(parameters));
  }

  /**
   * Generates a new Octet Sequence JSON Web Key on the fly based on the provided options.
   *
   * @param options Options used to generate the Octet Sequence JSON Web Key.
   * @param parameters Optional Octet Sequence JSON Web Key Parameters.
   */
  public static async generate(
    options: GenerateOCTJsonWebKeyOptions,
    parameters: Partial<JsonWebKeyParameters> = {},
  ): Promise<OCTJsonWebKey> {
    if (!Number.isInteger(options.length)) {
      throw new TypeError('The length must be an integer.');
    }

    if (options.length <= 0) {
      throw new TypeError('The length must be greater than zero.');
    }

    const bytes = await randomBytesAsync(options.length);

    const secretKeyParameters = <OCTJsonWebKeyParameters>{ kty: 'oct', k: bytes.toString('base64url') };

    const octJsonWebKeyParameters: OCTJsonWebKeyParameters = Object.assign(
      secretKeyParameters,
      Object.removeNullishValues(parameters),
    );

    return new OCTJsonWebKey(octJsonWebKeyParameters);
  }

  /**
   * Returns the parameters of the Octet Sequence JSON Web Key in a JSON-friendly format.
   *
   * @param options Options used to customize the returned Octet Sequence JSON Web Key Parameters.
   * @returns Octet Sequence JSON Web Key Parameters.
   */
  public override toJSON(options?: JsonWebKeyToJSONOptions): OCTJsonWebKeyParameters {
    return <OCTJsonWebKeyParameters>super.toJSON(options);
  }

  /**
   * Validates the provided Octet Sequence JSON Web Key Parameters.
   *
   * @param parameters Parameters of the Octet Sequence JSON Web Key.
   */
  protected override validate(parameters: OCTJsonWebKeyParameters): void {
    if (parameters.kty !== 'oct') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "kty".');
    }

    if (typeof parameters.k !== 'string' || Buffer.byteLength(parameters.k, 'base64url') === 0) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "k".');
    }

    super.validate(parameters);
  }

  /**
   * Returns the parameters used to calculate the Thumbprint of the
   * Octet Sequence JSON Web Key in lexicographic order.
   */
  protected getThumbprintParameters(): OCTJsonWebKeyParameters {
    return { k: this.k, kty: this.kty };
  }

  /**
   * Returns the list of all private parameters of the Octet Sequence JSON Web Key.
   */
  protected getPrivateParameters(): string[] {
    return [];
  }
}
