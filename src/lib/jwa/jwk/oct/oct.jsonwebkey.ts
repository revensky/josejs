import { Buffer } from 'buffer';

import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { OCTJsonWebKeyParameters } from './oct.jsonwebkey.parameters';

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
   * Returns the parameters of the Octet Sequence JSON Web Key in a JSON-friendly format.
   *
   * @returns Octet Sequence JSON Web Key Parameters.
   */
  public override toJSON(): OCTJsonWebKeyParameters {
    return super.toJSON() as OCTJsonWebKeyParameters;
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
}
