import { Buffer } from 'buffer';
import { createHash, X509Certificate } from 'crypto';
import https from 'https';

import { Object } from '@revensky/primitives';

import { InvalidJsonWebKeyException } from '../exceptions/invalid-jsonwebkey.exception';
import { EcJwkBackend } from '../jwa/jwk/ec/ec-jwk.backend';
import { JwkBackend } from '../jwa/jwk/jwk.backend';
import { OctJwkBackend } from '../jwa/jwk/oct/oct-jwk.backend';
import { OkpJwkBackend } from '../jwa/jwk/okp/okp-jwk.backend';
import { RsaJwkBackend } from '../jwa/jwk/rsa/rsa-jwk.backend';
import { JweAlg } from '../jwe/jwe.alg';
import { JweEnc } from '../jwe/jwe.enc';
import { JwsAlg } from '../jws/jws.alg';
import { JwkKeyOp } from './jwk.key-op';
import { JwkKty } from './jwk.kty';
import { JwkParameters } from './jwk.parameters';
import { JwkUse } from './jwk.use';

/**
 * JSON Web Key Implementation.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html | JSON Web Key}
 */
export class JsonWebKey<T extends JwkParameters = JwkParameters> {
  /**
   * Supported JSON Web Key Backends.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1 | JWK Key Types}
   */
  private static readonly backends: Record<JwkKty, JwkBackend> = {
    EC: new EcJwkBackend(),
    OKP: new OkpJwkBackend(),
    RSA: new RsaJwkBackend(),
    oct: new OctJwkBackend(),
  };

  /**
   * Supported JSON Web Key Public Key Uses.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.2 | JWK Public Key Uses}
   */
  private static readonly jwkUses: JwkUse[] = ['enc', 'sig'];

  /**
   * Supported JSON Web Key Key Operations.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3 | JWK Key Operations}
   */
  private static readonly jwkKeyOps: JwkKeyOp[] = [
    'decrypt',
    'deriveBits',
    'deriveKey',
    'encrypt',
    'sign',
    'unwrapKey',
    'verify',
    'wrapKey',
  ];

  /**
   * Supported JSON Web Key Algorithms.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3 | JWS Algorithms}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-4 | JWE Key Management Algorithms}
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-5 | JWE Content Encryption Algorithms}
   */
  private static readonly jwkAlgs: (JweAlg | JweEnc | JwsAlg)[] = [
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
   * JSON Web Key Backend.
   */
  private readonly backend: JwkBackend;

  /**
   * JSON Web Key Parameters.
   */
  public readonly parameters: T;

  /**
   * Instantiates a new JSON Web Key with the provided parameters.
   *
   * @param parameters JSON Web Key Parameters.
   */
  public constructor(parameters: T) {
    this.validate(parameters);

    this.backend = JsonWebKey.backends[parameters.kty];
    this.backend.validate(parameters);

    this.parameters = Object.removeNullishValues(parameters);
  }

  /**
   * Checks if the provided data is a valid JSON Web Key Parameters object.
   *
   * @param data Data to be checked.
   * @returns Whether or not the provided data is a valid JSON Web Key Parameters object.
   */
  public static isJwk(data: unknown): data is JwkParameters {
    return (
      Object.isPlain(data) &&
      Object.hasOwn(data, 'kty') &&
      typeof Reflect.get(data, 'kty') === 'string' &&
      Object.hasOwn(this.backends, Reflect.get(data, 'kty'))
    );
  }

  /**
   * Calculates the Thumbprint of the JSON Web Key.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7638.html | JWK Thumbprint}
   *
   * @param hashFunction Name of the OpenSSL Hash Function used to calculate the thumbprint.
   * @returns Thumbprint of the JSON Web Key.
   */
  public getThumbprint(hashFunction: string): Buffer {
    const thumbprintParameters = this.backend.getThumbprintParameters(this.parameters);
    return createHash(hashFunction).update(JSON.stringify(thumbprintParameters), 'utf8').digest();
  }

  /**
   * Returns the Parameters of the JSON Web Key.
   *
   * @param privateKey Exports the parameters of the Private Key together with the Public Key.
   * @returns JSON Web Key Parameters.
   */
  public toJSON(privateKey?: true): T {
    let entries = Object.entries(this.parameters);

    if (privateKey !== true) {
      const privateParameters: string[] = this.backend.getPrivateParameters();
      entries = entries.filter(([parameter]) => !privateParameters.includes(parameter));
    }

    return Object.removeNullishValues(<T>Object.fromEntries(entries));
  }

  /**
   * Validates the provided JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   */
  private validate(parameters: T): void {
    // #region Existence Checks
    if (typeof parameters.kty !== 'string' || !Object.hasOwn(JsonWebKey.backends, parameters.kty)) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "kty".');
    }

    if (
      typeof parameters.use !== 'undefined' &&
      (typeof parameters.use !== 'string' || !JsonWebKey.jwkUses.includes(parameters.use))
    ) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "use".');
    }

    if (
      typeof parameters.key_ops !== 'undefined' &&
      (!Array.isArray(parameters.key_ops) ||
        parameters.key_ops.length === 0 ||
        parameters.key_ops.some((keyOp) => typeof keyOp !== 'string' || !JsonWebKey.jwkKeyOps.includes(keyOp)) ||
        new Set(parameters.key_ops).size !== parameters.key_ops.length)
    ) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "key_ops".');
    }

    if (
      typeof parameters.alg !== 'undefined' &&
      (typeof parameters.alg !== 'string' || !JsonWebKey.jwkAlgs.includes(parameters.alg))
    ) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "alg".');
    }

    if (typeof parameters.kid !== 'undefined' && typeof parameters.kid !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "kid".');
    }

    if (typeof parameters.x5u !== 'undefined' && typeof parameters.x5u !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x5u".');
    }

    if (
      typeof parameters.x5c !== 'undefined' &&
      (!Array.isArray(parameters.x5c) ||
        parameters.x5c.length === 0 ||
        parameters.x5c.some((x509Certificate) => typeof x509Certificate !== 'string'))
    ) {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x5c".');
    }

    if (typeof parameters.x5t !== 'undefined' && typeof parameters.x5t !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x5t".');
    }

    if (typeof parameters['x5t#S256'] !== 'undefined' && typeof parameters['x5t#S256'] !== 'string') {
      throw new InvalidJsonWebKeyException('Invalid json web key parameter "x5t#S256".');
    }
    // #endregion

    // #region Business Rules
    if (typeof parameters.use !== 'undefined' && typeof parameters.key_ops !== 'undefined') {
      this.validateUseAndKeyOpsParameters(parameters);
    }

    if (['x5u', 'x5c', 'x5t', 'x5t#S256'].some((parameter) => Object.hasOwn(parameters, parameter))) {
      this.validateX509CertificateParameters(parameters);
    }
    // #endregion
  }

  /**
   * Checks if the combination of Public Key Use and Key Operations provided is valid.
   *
   * @param parameters JSON Web Key Parameters.
   */
  private validateUseAndKeyOpsParameters(parameters: JwkParameters): void {
    const sigOps: JwkKeyOp[] = ['sign', 'verify'];
    const encOps: JwkKeyOp[] = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];

    if (
      (parameters.use! === 'sig' && parameters.key_ops!.some((keyOp) => !sigOps.includes(keyOp))) ||
      (parameters.use! === 'enc' && parameters.key_ops!.some((keyOp) => !encOps.includes(keyOp)))
    ) {
      throw new InvalidJsonWebKeyException('Invalid combination of json web key parameters "use" and "key_ops".');
    }
  }

  /**
   * Checks if the provided X.509 Certificate JSON Web Key Parameters are valid.
   *
   * @param parameters JSON Web Key Parameters.
   */
  private validateX509CertificateParameters(parameters: JwkParameters): void {
    // Cannot use both "x5u" and "x5c" parameters.
    if (typeof parameters.x5u !== 'undefined' && typeof parameters.x5c !== 'undefined') {
      throw new InvalidJsonWebKeyException('The parameters "x5u" and "x5c" cannot be used together.');
    }

    // Cannot not use "x5t" or "x5t#S256" anot not provide one of "x5u" or "x5c".
    if (typeof parameters.x5u === 'undefined' && typeof parameters.x5c === 'undefined') {
      if (typeof parameters.x5t !== 'undefined' && typeof parameters['x5t#S256'] !== 'undefined') {
        throw new InvalidJsonWebKeyException('The parameters "x5t" and "x5t#S256" require one of "x5u" or "x5c".');
      }

      if (typeof parameters.x5t !== 'undefined') {
        throw new InvalidJsonWebKeyException('The parameter "x5t" requires one of "x5u" or "x5c".');
      }

      if (typeof parameters['x5t#S256'] !== 'undefined') {
        throw new InvalidJsonWebKeyException('The parameter "x5t#S256" requires one of "x5u" or "x5c".');
      }
    }

    let x509CertificateChain!: X509Certificate[];

    if (typeof parameters.x5u !== 'undefined') {
      x509CertificateChain = this.getX5UCertificateChain(parameters.x5u);
    }

    if (typeof parameters.x5c !== 'undefined') {
      try {
        x509CertificateChain = parameters.x5c.map((pemCertificate) => {
          return new X509Certificate(Buffer.from(pemCertificate, 'base64'));
        });
      } catch (exception: unknown) {
        throw new InvalidJsonWebKeyException('The json web key parameter "x5c" contains an invalid certificate.', {
          cause: exception,
        });
      }
    }

    x509CertificateChain.forEach((x509Certificate) => {
      const now = new Date();

      if (x509Certificate.validFromDate > now) {
        throw new InvalidJsonWebKeyException('The provided certificate is not yet valid.');
      }

      if (x509Certificate.validToDate < now) {
        throw new InvalidJsonWebKeyException('The provided certificate is expired.');
      }
    });

    // #region First certificate checks
    // TODO: Add keyUsage check when available.
    const firstCertificate = x509CertificateChain[0]!;

    if (Object.entries(firstCertificate.publicKey.export({ format: 'jwk' })).some(([k, v]) => parameters[k] !== v)) {
      throw new InvalidJsonWebKeyException('The provided certificate did not sign the json web key.');
    }

    if (
      typeof parameters.x5t !== 'undefined' &&
      Buffer.from(firstCertificate.fingerprint.replaceAll(':', ''), 'hex').toString('base64url') !== parameters.x5t
    ) {
      throw new InvalidJsonWebKeyException('The certificate\'s SHA-1 Fingerprint does not match the value at "x5t".');
    }

    if (
      typeof parameters['x5t#S256'] !== 'undefined' &&
      Buffer.from(firstCertificate.fingerprint256.replaceAll(':', ''), 'hex').toString('base64url') !==
        parameters['x5t#S256']
    ) {
      throw new InvalidJsonWebKeyException(
        'The certificate\'s SHA-256 Fingerprint does not match the value at "x5t#S256".',
      );
    }
    // #endregion

    // #region Remaining certificates checks
    for (let i = 0; i < x509CertificateChain.length - 1; i++) {
      if (!x509CertificateChain[i]!.verify(x509CertificateChain[i + 1]!.publicKey)) {
        throw new InvalidJsonWebKeyException('A certificate in the chain was not successfully verified.');
      }
    }
    // #endregion
  }

  /**
   * Accesses the provided URL and parses the X.509 Certificate Chain.
   *
   * @param x5u X.509 Certificate Chain URL provided in the JSON Web Key Parameters.
   * @returns X.509 Certificate Chain from the URL.
   */
  private getX5UCertificateChain(x5u: string): X509Certificate[] {
    let x509CertificateChain!: X509Certificate[];

    https.get(x5u, (res) => {
      let responseBody = '';

      res.on('data', (chunk) => (responseBody += chunk));
      res.on('end', () => {
        try {
          x509CertificateChain =
            responseBody
              .replaceAll('\n', '')
              .match(/-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----/)!
              .map((x509Certificate) => x509Certificate.replaceAll(/-----\w+ CERTIFICATE-----/g, ''))
              .map((pemCertificate) => new X509Certificate(Buffer.from(pemCertificate, 'base64'))) ?? null;
        } catch (exception: unknown) {
          throw new InvalidJsonWebKeyException('The json web key parameter "x5u" contains an invalid certificate.', {
            cause: exception,
          });
        }
      });
    });

    return x509CertificateChain;
  }
}
