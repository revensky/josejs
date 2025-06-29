import { ECJsonWebKey } from '../jwa/jwk/ec/ec.jsonwebkey';
import { GenerateECJsonWebKeyOptions } from '../jwa/jwk/ec/generate-ec-jsonwebkey.options';
import { GenerateOCTJsonWebKeyOptions } from '../jwa/jwk/oct/generate-oct-jsonwebkey.options';
import { OCTJsonWebKey } from '../jwa/jwk/oct/oct.jsonwebkey';
import { GenerateOKPJsonWebKeyOptions } from '../jwa/jwk/okp/generate-okp-jsonwebkey.options';
import { OKPJsonWebKey } from '../jwa/jwk/okp/okp.jsonwebkey';
import { GenerateRSAJsonWebKeyOptions } from '../jwa/jwk/rsa/generate-rsa-jsonwebkey.options';
import { RSAJsonWebKey } from '../jwa/jwk/rsa/rsa.jsonwebkey';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JsonWebKeyParameters } from '../jwk/jsonwebkey.parameters';
import { JwkKty } from '../jwk/jwk-kty.type';

/**
 * Generates a new Elliptic Curve JSON Web Key based on the provided options.
 *
 * @param kty Elliptic Curve JSON Web Key Type.
 * @param options Options used to generate the Elliptic Curve JSON Web Key.
 * @param parameters Optional JSON Web Key Parameters.
 * @returns Generated Elliptic Curve JSON Web Key.
 */
export async function generateJsonWebKey(
  kty: 'EC',
  options: GenerateECJsonWebKeyOptions,
  parameters?: Partial<JsonWebKeyParameters>,
): Promise<ECJsonWebKey>;

/**
 * Generates a new Octet Key Pair JSON Web Key based on the provided options.
 *
 * @param kty Octet Key Pair JSON Web Key Type.
 * @param options Options used to generate the Octet Key Pair JSON Web Key.
 * @param parameters Optional JSON Web Key Parameters.
 * @returns Generated Octet Key Pair JSON Web Key.
 */
export async function generateJsonWebKey(
  kty: 'OKP',
  options: GenerateOKPJsonWebKeyOptions,
  parameters?: Partial<JsonWebKeyParameters>,
): Promise<OKPJsonWebKey>;

/**
 * Generates a new RSA JSON Web Key based on the provided options.
 *
 * @param kty RSA JSON Web Key Type.
 * @param options Options used to generate the RSA JSON Web Key.
 * @param parameters Optional JSON Web Key Parameters.
 * @returns Generated RSA JSON Web Key.
 */
export async function generateJsonWebKey(
  kty: 'RSA',
  options: GenerateRSAJsonWebKeyOptions,
  parameters?: Partial<JsonWebKeyParameters>,
): Promise<RSAJsonWebKey>;

/**
 * Generates a new Octet Sequence JSON Web Key based on the provided options.
 *
 * @param kty Octet Sequence JSON Web Key Type.
 * @param options Options used to generate the Octet Sequence JSON Web Key.
 * @param parameters Optional JSON Web Key Parameters.
 * @returns Generated Octet Sequence JSON Web Key.
 */
export async function generateJsonWebKey(
  kty: 'oct',
  options: GenerateOCTJsonWebKeyOptions,
  parameters?: Partial<JsonWebKeyParameters>,
): Promise<OCTJsonWebKey>;

/**
 * Generates a new JSON Web Key based on the provided options.
 *
 * @param kty JSON Web Key Type.
 * @param options Options used to generate the JSON Web Key.
 * @param parameters Optional JSON Web Key Parameters.
 * @returns Generated JSON Web Key.
 */
export async function generateJsonWebKey(
  kty: JwkKty,
  options: Record<string, unknown>,
  parameters?: Partial<JsonWebKeyParameters>,
): Promise<JsonWebKey> {
  switch (kty) {
    case 'EC':
      return await ECJsonWebKey.generate(<GenerateECJsonWebKeyOptions>options, parameters);

    case 'OKP':
      return await OKPJsonWebKey.generate(<GenerateOKPJsonWebKeyOptions>options, parameters);

    case 'RSA':
      return await RSAJsonWebKey.generate(<GenerateRSAJsonWebKeyOptions>options, parameters);

    case 'oct':
      return await OCTJsonWebKey.generate(<GenerateOCTJsonWebKeyOptions>options, parameters);

    default:
      throw new TypeError(`Unsupported JSON Web Key Type "${String(kty)}".`);
  }
}
