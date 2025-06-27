import { Buffer } from 'buffer';

import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { ECJsonWebKeyParameters } from './ec.jsonwebkey.parameters';
import { JwkCrv } from './jwk-crv.type';

/**
 * Elliptic Curve JSON Web Key Implementation.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2 | EC JWK}
 */
export class ECJsonWebKey extends JsonWebKey {
  /**
   * Supported NodeJS Crypto Key Elliptic Curves.
   */
  static readonly #curves: Record<Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>, string> = {
    'P-256': 'prime256v1',
    'P-384': 'secp384r1',
    'P-521': 'secp521r1',
  };

  /**
   * Ellipitic Curve Parameters' lengths.
   */
  static readonly #lengths: Record<Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>, number> = {
    'P-256': 32,
    'P-384': 48,
    'P-521': 64,
  };

  /**
   * JSON Web Key Type.
   */
  public readonly kty!: 'EC';

  /**
   * Elliptic Curve Name.
   */
  public readonly crv!: Extract<JwkCrv, 'P-256' | 'P-384' | 'P-521'>;

  /**
   * Elliptic Curve X Coordinate.
   */
  public readonly x!: string;

  /**
   * Elliptic Curve Y Coordinate.
   */
  public readonly y!: string;

  /**
   * Elliptic Curve Private Value.
   */
  public readonly d?: string;

  /**
   * Instantiates a new Elliptic Curve JSON Web Key based on the provided Parameters.
   *
   * @param parameters Elliptic Curve JSON Web Key Parameters.
   */
  public constructor(parameters: ECJsonWebKey | ECJsonWebKeyParameters) {
    super(parameters);
    Object.assign(this, Object.removeNullishValues(parameters));
  }

  /**
   * Returns the parameters of the Elliptic Curve JSON Web Key in a JSON-friendly format.
   *
   * @returns Elliptic Curve JSON Web Key Parameters.
   */
  public override toJSON(): ECJsonWebKeyParameters {
    return super.toJSON() as ECJsonWebKeyParameters;
  }

  /**
   * Validates the provided Elliptic Curve JSON Web Key Parameters.
   *
   * @param parameters Parameters of the Elliptic Curve JSON Web Key.
   */
  protected override validate(parameters: ECJsonWebKeyParameters): void {
    if (parameters.kty !== 'EC') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "kty".');
    }

    if (typeof parameters.crv !== 'string' || !Object.hasOwn(ECJsonWebKey.#curves, parameters.crv)) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "crv".');
    }

    const parameterLength = ECJsonWebKey.#lengths[parameters.crv];

    if (typeof parameters.x !== 'string' || Buffer.byteLength(parameters.x, 'base64url') !== parameterLength) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x".');
    }

    if (typeof parameters.y !== 'string' || Buffer.byteLength(parameters.y, 'base64url') !== parameterLength) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "y".');
    }

    if (
      typeof parameters.d !== 'undefined' &&
      (typeof parameters.d !== 'string' || Buffer.byteLength(parameters.d, 'base64url') !== parameterLength)
    ) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "d".');
    }

    super.validate(parameters);
  }

  /**
   * Returns the parameters used to calculate the Thumbprint of the
   * Elliptic Curve JSON Web Key in lexicographic order.
   */
  protected getThumbprintParameters(): ECJsonWebKeyParameters {
    return { crv: this.crv, kty: this.kty, x: this.x, y: this.y };
  }
}
