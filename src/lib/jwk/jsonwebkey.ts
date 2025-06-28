import { Buffer } from 'buffer';
import { createHash } from 'crypto';

import { JSON, Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../exceptions/invalid-jsonwebkey.exception';
import { JweAlg } from '../jwe/jwe-alg.type';
import { JweEnc } from '../jwe/jwe-enc.type';
import { JwsAlg } from '../jws/jws-alg.type';
import { JsonWebKeyParameters } from './jsonwebkey.parameters';
import { JwkKeyOp } from './jwk-keyop.type';
import { JwkKty } from './jwk-kty.type';
import { JwkUse } from './jwk-use.type';

/**
 * JSON Web Key Implementation.
 *
 * The JSON Web Key is an abstract representation of a Cryptographic Key.
 *
 * It is used to perform cryptographic operations on the data handled by
 * the JSON Web Encryption and JSON Web Signature functionalities.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html | RFC 7517}
 */
export abstract class JsonWebKey {
  /**
   * Supported algorithms for the following operations.
   *
   * * JSON Web Encryption Key Management
   * * JSON Web Encryption Content Encryption
   * * JSON Web Signature
   */
  static readonly #supportedAlgs: (JweAlg | JweEnc | JwsAlg)[] = [
    'A128CBC-HS256',
    'A128GCM',
    'A128GCMKW',
    'A128KW',
    'A192CBC-HS384',
    'A192GCM',
    'A192GCMKW',
    'A192KW',
    'A256CBC-HS512',
    'A256GCM',
    'A256GCMKW',
    'A256KW',
    'ECDH-ES',
    'ECDH-ES+A128KW',
    'ECDH-ES+A192KW',
    'ECDH-ES+A256KW',
    'ES256',
    'ES384',
    'ES512',
    'EdDSA',
    'HS256',
    'HS384',
    'HS512',
    'PBES2-HS256+A128KW',
    'PBES2-HS384+A192KW',
    'PBES2-HS512+A256KW',
    'PS256',
    'PS384',
    'PS512',
    'RS256',
    'RS384',
    'RS512',
    'RSA-OAEP',
    'RSA-OAEP-256',
    'RSA-OAEP-384',
    'RSA-OAEP-512',
    'RSA1_5',
    'dir',
    'none',
  ];

  /**
   * JSON Web Key Type.
   */
  public abstract readonly kty: JwkKty;

  /**
   * Indicates whether a Public JSON Web Key is used for Plaintext Encryption or Signature Verification.
   */
  public use?: JwkUse;

  /**
   * Operations for which the JSON Web Key are intended to be used.
   */
  public key_ops?: JwkKeyOp[];

  /**
   * Indicates the algorithm allowed for use by this JSON Web Key for the following operations.
   *
   * * JSON Web Encryption Key Management
   * * JSON Web Encryption Content Encryption
   * * JSON Web Signature
   */
  public alg?: JweAlg | JweEnc | JwsAlg;

  /**
   * Identifier of the JSON Web Key.
   */
  public kid?: string;

  /**
   * URL of the X.509 certificate of the JSON Web Key.
   */
  public x5u?: string;

  /**
   * Chain of X.509 certificates of the JSON Web Key.
   */
  public x5c?: string[];

  /**
   * SHA-1 Thumbprint of the X.509 certificate of the JSON Web Key.
   */
  public x5t?: string;

  /**
   * SHA-256 Thumbprint of the X.509 certificate of the JSON Web Key.
   */
  public 'x5t#S256'?: string;

  /**
   * Additional JSON Web Key Parameters.
   */
  [parameter: string]: unknown;

  /**
   * Thumbprint of the JSON Web Key.
   */
  #thumbprint!: Buffer;

  /**
   * Instantiates a new JSON Web Key based on the provided Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   */
  // Javascript doesn't play nice, so the assignment must be done at the child class.
  public constructor(parameters: JsonWebKey | JsonWebKeyParameters) {
    if (parameters instanceof JsonWebKey) {
      return parameters;
    }

    this.validate(parameters);
  }

  /**
   * Checks if the provided data has the minimum valid format of a JSON Web Key object.
   *
   * @param data Data to be checked.
   */
  public static isJsonWebKey(data: unknown): data is JsonWebKey | JsonWebKeyParameters {
    return data instanceof JsonWebKey || (Object.isPlain(data) && Object.hasOwn(data, 'kty'));
  }

  /**
   * Generates a new JSON Web Key on the fly based on the provided options.
   *
   * @param options Options used to generate the JSON Web Key.
   * @param parameters Optional JSON Web Key Parameters.
   */
  public static async generate(
    // @ts-ignore
    options: Record<string, unknown>,
    // @ts-ignore
    parameters?: Partial<JsonWebKeyParameters>,
  ): Promise<JsonWebKey> {
    throw new TypeError('Method not implemented.');
  }

  /**
   * Returns the Thumbprint of the Public Parameters of the JSON Web Key.
   *
   * The hash algorithm **SHA-256** is used to generate the thumbprint.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7638.html | RFC 7638}
   */
  public getThumbprint(): Buffer {
    if (!Buffer.isBuffer(this.#thumbprint)) {
      this.#thumbprint = createHash('sha256').update(JSON.stringify(this.getThumbprintParameters()), 'utf8').digest();
    }

    return this.#thumbprint;
  }

  /**
   * Returns the parameters of the JSON Web Key in a JSON-friendly format.
   *
   * @returns JSON Web Key Parameters.
   */
  public toJSON(): JsonWebKeyParameters {
    return <JsonWebKeyParameters>(
      Object.fromEntries(
        Object.entries(this).filter(([, value]) => !['function', 'symbol', 'undefined'].includes(typeof value)),
      )
    );
  }

  /**
   * Validates the provided JSON Web Key Parameters.
   *
   * @param parameters Parameters of the JSON Web Key.
   */
  protected validate(parameters: JsonWebKeyParameters): void {
    // #region Existence Checks
    if (typeof parameters.use !== 'undefined' && typeof parameters.use !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "use".');
    }

    if (
      typeof parameters.key_ops !== 'undefined' &&
      (!Array.isArray(parameters.key_ops) ||
        parameters.key_ops.length === 0 ||
        parameters.key_ops.some((keyOp) => typeof keyOp !== 'string') ||
        new Set(parameters.key_ops).size !== parameters.key_ops.length)
    ) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "key_ops".');
    }

    if (typeof parameters.alg !== 'undefined' && typeof parameters.alg !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "alg".');
    }

    if (typeof parameters.kid !== 'undefined' && typeof parameters.kid !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "kid".');
    }

    // TODO: Add support for X.509 Certificate (Chain) parameters.
    if (typeof parameters.x5u !== 'undefined') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x5u".');
    }

    if (typeof parameters.x5c !== 'undefined') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x5c".');
    }

    if (typeof parameters.x5t !== 'undefined') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x5t".');
    }

    if (typeof parameters['x5t#S256'] !== 'undefined') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x5t#S256".');
    }
    // #endregion

    // #region Business Cases
    if (typeof parameters.use !== 'undefined' && typeof parameters.key_ops !== 'undefined') {
      const encOps: JwkKeyOp[] = ['decrypt', 'deriveBits', 'deriveKey', 'encrypt', 'unwrapKey', 'wrapKey'];
      const sigOps: JwkKeyOp[] = ['sign', 'verify'];

      if (
        (parameters.use === 'enc' && parameters.key_ops.some((keyOp) => !encOps.includes(keyOp))) ||
        (parameters.use === 'sig' && parameters.key_ops.some((keyOp) => !sigOps.includes(keyOp)))
      ) {
        throw new InvalidJsonWebKeyException('Invalid combination of "use" and "key_ops".');
      }
    }

    if (typeof parameters.alg !== 'undefined' && !JsonWebKey.#supportedAlgs.includes(parameters.alg)) {
      throw new InvalidJsonWebKeyException(`Unsupported value for json web key parameter "alg".`);
    }
    // #endregion
  }

  /**
   * Returns the parameters used to calculate the Thumbprint of the JSON Web Key in lexicographic order.
   */
  protected abstract getThumbprintParameters(): JsonWebKeyParameters;
}
