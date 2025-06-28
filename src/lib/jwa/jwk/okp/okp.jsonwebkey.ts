import { Buffer } from 'buffer';
import { generateKeyPair } from 'crypto';
import { promisify } from 'util';

import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JwkCrv } from '../ec/jwk-crv.type';
import { GenerateOKPJsonWebKeyOptions } from './generate-okp-jsonwebkey.options';
import { OKPJsonWebKeyParameters } from './okp.jsonwebkey.parameters';

const generateKeyPairAsync = promisify(generateKeyPair);

/**
 * Octet Key Pair JSON Web Key Implementation.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc8037.html#section-2 | OKP JWK}
 */
export class OKPJsonWebKey extends JsonWebKey {
  /**
   * Supported NodeJS Crypto Key Elliptic Curves.
   */
  static readonly #curves: Record<Extract<JwkCrv, 'Ed25519' | 'Ed448' | 'X25519' | 'X448'>, string> = {
    Ed25519: 'ed25519',
    Ed448: 'ed448',
    X25519: 'x25519',
    X448: 'x448',
  };

  /**
   * Ellipitic Curve Parameters' lengths.
   */
  static readonly #lengths: Record<Extract<JwkCrv, 'Ed25519' | 'Ed448' | 'X25519' | 'X448'>, number> = {
    Ed25519: 32,
    Ed448: 57,
    X25519: 32,
    X448: 56,
  };

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
   * Instantiates a new Octet Key Pair JSON Web Key based on the provided Parameters.
   *
   * @param parameters Octet Key Pair JSON Web Key Parameters.
   */
  public constructor(parameters: OKPJsonWebKey | OKPJsonWebKeyParameters) {
    super(parameters);
    Object.assign(this, Object.removeNullishValues(parameters));
  }

  /**
   * Generates a new Octet Key Pair JSON Web Key on the fly based on the provided options.
   *
   * @param options Options used to generate the Octet Key Pair JSON Web Key.
   * @param parameters Optional Octet Key Pair JSON Web Key Parameters.
   */
  public static override async generate(
    options: GenerateOKPJsonWebKeyOptions,
    parameters?: Partial<OKPJsonWebKeyParameters>,
  ): Promise<OKPJsonWebKey> {
    if (!Object.hasOwn(this.#curves, options.curve)) {
      throw new TypeError(`Unsupported Elliptic Curve "${String(options.curve)}".`);
    }

    const { privateKey } = await generateKeyPairAsync(<any>this.#curves[options.curve]);
    const privateKeyParameters = privateKey.export({ format: 'jwk' }) as OKPJsonWebKeyParameters;

    const okpJsonWebKeyParameters: OKPJsonWebKeyParameters = Object.assign(privateKeyParameters, parameters);

    return new OKPJsonWebKey(okpJsonWebKeyParameters);
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

    if (typeof parameters.crv !== 'string' || !Object.hasOwn(OKPJsonWebKey.#curves, parameters.crv)) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "crv".');
    }

    const parameterLength = OKPJsonWebKey.#lengths[parameters.crv];

    if (typeof parameters.x !== 'string' || Buffer.byteLength(parameters.x, 'base64url') !== parameterLength) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x".');
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
   * Octet Key Pair JSON Web Key in lexicographic order.
   */
  protected getThumbprintParameters(): OKPJsonWebKeyParameters {
    return { crv: this.crv, kty: this.kty, x: this.x };
  }
}
