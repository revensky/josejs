import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JwkCrv } from '../ec/jwk-crv.type';
import { OKPJsonWebKeyParameters } from './okp.jsonwebkey.parameters';

/**
 * Octet Key Pair JSON Web Key Implementation.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2 | OKP JWK}
 */
export class OKPJsonWebKey extends JsonWebKey {
  /**
   * JSON Web Key Type.
   */
  public readonly kty!: 'OKP';

  /**
   * Elliptic Curve Name.
   */
  public readonly crv!: Extract<JwkCrv, 'Ed25519' | 'Ed448' | 'X25519' | 'X448'>;

  /**
   * Elliptic Curve X Coordinate.
   */
  public readonly x!: string;

  /**
   * Elliptic Curve Private Value.
   */
  public readonly d?: string;

  /**
   * Elliptic Curves supported by the Octet Key Pair JSON Web Key.
   */
  private get supportedEllipticCurves(): Extract<JwkCrv, 'Ed25519' | 'Ed448' | 'X25519' | 'X448'>[] {
    return ['Ed25519', 'Ed448', 'X25519', 'X448'];
  }

  /**
   * Instantiates a new Octet Key Pair JSON Web Key based on the provided Parameters.
   *
   * @param parameters Octet Key Pair JSON Web Key Parameters.
   */
  public constructor(parameters: OKPJsonWebKey | OKPJsonWebKeyParameters) {
    super(parameters);
    Object.assign(this, Object.removeNullishValues(parameters));
  }

  /**
   * Returns the parameters of the Octet Key Pair JSON Web Key in a JSON-friendly format.
   *
   * @returns Octet Key Pair JSON Web Key Parameters.
   */
  public override toJSON(): OKPJsonWebKeyParameters {
    return super.toJSON() as OKPJsonWebKeyParameters;
  }

  /**
   * Validates the provided Octet Key Pair JSON Web Key Parameters.
   *
   * @param parameters Parameters of the Octet Key Pair JSON Web Key.
   */
  protected override validate(parameters: OKPJsonWebKeyParameters): void {
    if (parameters.kty !== 'OKP') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "kty".');
    }

    if (typeof parameters.crv !== 'string' || !this.supportedEllipticCurves.includes(parameters.crv)) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "crv".');
    }

    if (typeof parameters.x !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x".');
    }

    if (typeof parameters.d !== 'undefined' && typeof parameters.d !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "d".');
    }

    super.validate(parameters);
  }
}
