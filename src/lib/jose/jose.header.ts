import { InvalidJoseHeaderException } from '../exceptions/invalid-jose-header.exception';
import { JsonWebKey } from '../jwk/jsonwebkey';
import { JwkParameters } from '../jwk/jwk.parameters';

/**
 * JSON Web Signature Header Parameters.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4 | JWS JOSE Header}
 * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4 | JWE JOSE Header}
 */
export interface JoseHeader extends Record<string, unknown> {
  /**
   * URI that refers to a resource for a set of JSON-encoded public keys, one of which
   * corresponds to the key used to digitally sign the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.2 | JWS JWK Set URL JOSE Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.4 | JWE JWK Set URL JOSE Header Parameter}
   */
  jku?: string;

  /**
   * Public key that corresponds to the key used to digitally sign the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.3 | JWS JSON Web Key JOSE Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.5 | JWE JSON Web Key JOSE Header Parameter}
   */
  jwk?: JwkParameters;

  /**
   * Hint indicating which key was used to secure the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4 | JWS Key ID JOSE Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.6 | JWE Key ID JOSE Header Parameter}
   */
  kid?: string;

  /**
   * URI that refers to a resource for the X.509 public key certificate or certificate chain
   * corresponding to the key used to digitally sign the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.5 | JWS X.509 URL JOSE Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.7 | JWE X.509 URL JOSE Header Parameter}
   */
  x5u?: string;

  /**
   * X.509 public key certificate or certificate chain corresponding to the key
   * used to digitally sign the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6 | JWS X.509 Certificate Chain JOSE Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.8 | JWE X.509 Certificate Chain JOSE Header Parameter}
   */
  x5c?: string[];

  /**
   * Base64url-encoded SHA-1 thumbprint of the DER encoding of the X.509 certificate
   * corresponding to the key used to digitally sign the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.7 | JWS X.509 Certificate SHA-1 Thumbprint JOSE Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.9 | JWE X.509 Certificate SHA-1 Thumbprint JOSE Header Parameter}
   */
  x5t?: string;

  /**
   * Base64url-encoded SHA-256 thumbprint of the DER encoding of the X.509 certificate
   * corresponding to the key used to digitally sign the JWS, or to encrypt the JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8 | JWS X.509 Certificate SHA-256 Thumbprint JOSE Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.10 | JWE X.509 Certificate SHA-256 Thumbprint JOSE Header Parameter}
   */
  'x5t#S256'?: string;

  /**
   * Declares the media type of the complete JWS or JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9 | JWS Type JOSE Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.11 | JWE Type JOSE Header Parameter}
   */
  typ?: string;

  /**
   * Declares the media type of the secured content of the JWS or JWE.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10 | JWS Content Type JOSE Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.12 | JWE Content Type JOSE Header Parameter}
   */
  cty?: string;

  /**
   * Defines the extension parameters that must be present in the JOSE Header.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11 | JWS Critical JOSE Header Parameter}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7516.html#section-4.1.13 | JWE Critical JOSE Header Parameter}
   */
  crit?: string[];
}

export namespace JoseHeader {
  /**
   * Validates the provided Protected JOSE Header.
   *
   * @param header Protected JOSE Header.
   */
  export function validateProtectedJoseHeader(header: JoseHeader): void {
    validateJoseHeader(header);

    if (typeof header.crit !== 'undefined') {
      const reservedJoseHeaderParameters = [
        'alg',
        'enc',
        'zip',
        'jku',
        'jwk',
        'kid',
        'x5u',
        'x5c',
        'x5t',
        'x5t#S256',
        'typ',
        'cty',
        'crit',
        'epk',
        'apu',
        'apv',
        'iv',
        'tag',
        'p2s',
        'p2c',
      ];

      if (
        !Array.isArray(header.crit) ||
        header.crit.length === 0 ||
        header.crit.some((parameter) => typeof parameter !== 'string') ||
        header.crit.some((parameter) => reservedJoseHeaderParameters.includes(parameter)) ||
        new Set(header.crit).size !== header.crit.length
      ) {
        throw new InvalidJoseHeaderException('Invalid jose header parameter "crit".');
      }

      header.crit.forEach((parameter) => {
        if (!Object.hasOwn(header, parameter)) {
          throw new InvalidJoseHeaderException(`Missing required jose header parameter "${parameter}".`);
        }
      });
    }
  }

  /**
   * Validates the provided Unprotected JOSE Header.
   *
   * @param header Unprotected JOSE Header.
   */
  export function validateUnprotectedJoseHeader(header: JoseHeader): void {
    validateJoseHeader(header);

    if (Object.hasOwn(header, 'crit')) {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "crit".');
    }
  }

  /**
   * Validates the provided JOSE Header.
   *
   * @param header JOSE Header.
   */
  function validateJoseHeader(header: JoseHeader): void {
    if (typeof header.jku !== 'undefined' && typeof header.jku !== 'string') {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "jku".');
    }

    if (typeof header.jwk !== 'undefined' && !JsonWebKey.isJwk(header.jwk)) {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "jwk".');
    }

    if (typeof header.kid !== 'undefined' && typeof header.kid !== 'string') {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "kid".');
    }

    if (typeof header.x5u !== 'undefined' && typeof header.x5u !== 'string') {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "x5u".');
    }

    if (
      typeof header.x5c !== 'undefined' &&
      (!Array.isArray(header.x5c) ||
        header.x5c.length === 0 ||
        header.x5c.some((x509Certificate) => typeof x509Certificate !== 'string'))
    ) {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "x5c".');
    }

    if (typeof header.x5t !== 'undefined' && typeof header.x5t !== 'string') {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "x5t".');
    }

    if (typeof header['x5t#S256'] !== 'undefined' && typeof header['x5t#S256'] !== 'string') {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "x5t#S256".');
    }

    if (typeof header.typ !== 'undefined' && typeof header.typ !== 'string') {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "typ".');
    }

    if (typeof header.cty !== 'undefined' && typeof header.cty !== 'string') {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "cty".');
    }
  }
}
