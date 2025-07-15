import { Buffer } from 'buffer';

import { Object, Set } from '@revensky/primitives';

import { InvalidJoseHeaderException } from '../exceptions/invalid-jose-header.exception';
import { JoseHeader } from '../jose/jose.header';
import { ES256JwsBackend } from '../jwa/jws/ecdsa/es256-jws.backend';
import { ES384JwsBackend } from '../jwa/jws/ecdsa/es384-jws.backend';
import { ES512JwsBackend } from '../jwa/jws/ecdsa/es512-jws.backend';
import { EdDSAJwsBackend } from '../jwa/jws/eddsa/eddsa-jws.backend';
import { HS256JwsBackend } from '../jwa/jws/hmac/hs256-jws.backend';
import { HS384JwsBackend } from '../jwa/jws/hmac/hs384-jws.backend';
import { HS512JwsBackend } from '../jwa/jws/hmac/hs512-jws.backend';
import { JwsBackend } from '../jwa/jws/jws.backend';
import { NoneJwsBackend } from '../jwa/jws/none/none-jws.backend';
import { PS256JwsBackend } from '../jwa/jws/rsassa/ps256-jws.backend';
import { PS384JwsBackend } from '../jwa/jws/rsassa/ps384-jws.backend';
import { PS512JwsBackend } from '../jwa/jws/rsassa/ps512-jws.backend';
import { RS256JwsBackend } from '../jwa/jws/rsassa/rs256-jws.backend';
import { RS384JwsBackend } from '../jwa/jws/rsassa/rs384-jws.backend';
import { RS512JwsBackend } from '../jwa/jws/rsassa/rs512-jws.backend';
import { JwsAlg } from './jws.alg';
import { JwsHeader } from './jws.header';
import { JwsHeaders } from './jws.headers';

/**
 * JSON Web Signature Implementation.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7515.html | JSON Web Signature}
 */
export class JsonWebSignature {
  /**
   * Supported JSON Web Signature Backends.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1 | JWS Algorithms}
   */
  private static readonly backends: Record<JwsAlg, JwsBackend> = {
    ES256: new ES256JwsBackend(),
    ES384: new ES384JwsBackend(),
    ES512: new ES512JwsBackend(),
    EdDSA: new EdDSAJwsBackend(),
    HS256: new HS256JwsBackend(),
    HS384: new HS384JwsBackend(),
    HS512: new HS512JwsBackend(),
    PS256: new PS256JwsBackend(),
    PS384: new PS384JwsBackend(),
    PS512: new PS512JwsBackend(),
    RS256: new RS256JwsBackend(),
    RS384: new RS384JwsBackend(),
    RS512: new RS512JwsBackend(),
    none: new NoneJwsBackend(),
  };

  /**
   * JSON Web Signature Protected JOSE Header.
   */
  public readonly protectedHeader?: JwsHeader;

  /**
   * JSON Web Signature Unprotected JOSE Header.
   */
  public readonly unprotectedHeader?: JwsHeader;

  /**
   * JSON Web Signature JOSE Headers.
   */
  public readonly headers?: JwsHeaders[];

  /**
   * JSON Web Signature Payload.
   */
  public readonly payload: Buffer;

  /**
   * JSON Web Signature Serialization Mode.
   */
  // @ts-expect-error
  // eslint-disable-next-line no-unused-private-class-members
  readonly #serialization: 'compact' | 'flattened' | 'general';

  /**
   * Instantiates a new Compact Serialization JSON Web Signature
   * with the provided JWS Protected JOSE Header and Payload.
   *
   * @param protectedHeader JWS Protected JOSE Header.
   * @param payload Buffer to be used as the Payload.
   */
  public constructor(protectedHeader: JwsHeader, payload: Buffer);

  /**
   * Instantiates a new General JSON Serialization JSON Web Signature
   * with the provided JWS Protected and Unprotected JOSE Headers and Payload.
   *
   * @param headers JWS Protected and Unprotected JOSE Headers.
   * @param payload Buffer to be used as the Payload.
   */
  public constructor(headers: JwsHeaders[], payload: Buffer);

  /**
   * Instantiates a new Flattened JSON Serialization JSON Web Signature
   * with the provided JWS Protected and Unprotected JOSE Header and Payload.
   *
   * @param protectedHeader JWS Protected JOSE Header.
   * @param unprotectedHeader JWS Unprotected JOSE Header.
   * @param payload Buffer to be used as the Payload.
   */
  public constructor(protectedHeader: JwsHeader, unprotectedHeader: JwsHeader, payload: Buffer);

  /**
   * Instantiates a new JSON Web Signature with the provided parameters.
   *
   * @param protectedHeaderOrHeaders JWS Protected JOSE Header or JWS Protected and Unprotected JOSE Headers.
   * @param payloadOrUnprotectedHeader Buffer to be used as the Payload or JWS Unprotected JOSE Header.
   * @param payload Buffer to be used as the Payload.
   */
  public constructor(
    protectedHeaderOrHeaders: JwsHeader | JwsHeaders[],
    payloadOrUnprotectedHeader: Buffer | JwsHeader,
    payload?: Buffer,
  ) {
    switch (true) {
      case Object.isPlain(protectedHeaderOrHeaders) && Buffer.isBuffer(payloadOrUnprotectedHeader):
        this.validateProtectedJwsJoseHeader(<JwsHeader>protectedHeaderOrHeaders);

        this.protectedHeader = <JwsHeader>protectedHeaderOrHeaders;
        this.payload = payloadOrUnprotectedHeader;

        this.#serialization = 'compact';

        break;

      case Array.isArray(protectedHeaderOrHeaders) && Buffer.isBuffer(payloadOrUnprotectedHeader):
        protectedHeaderOrHeaders.forEach((headers) => {
          if (Object.isPlain(headers.protectedHeader)) {
            this.validateProtectedJwsJoseHeader(headers.protectedHeader);
          }

          if (Object.isPlain(headers.unprotectedHeader)) {
            this.validateUnprotectedJwsJoseHeader(headers.unprotectedHeader);
          }

          this._checkIfProtectedAndUnprotectedHeadersAreDisjoint(headers.protectedHeader, headers.unprotectedHeader);
        });

        this.headers = protectedHeaderOrHeaders;
        this.payload = payloadOrUnprotectedHeader;

        this.#serialization = 'general';

        break;

      case Object.isPlain(protectedHeaderOrHeaders) &&
        Object.isPlain(payloadOrUnprotectedHeader) &&
        Buffer.isBuffer(payload):
        this.validateProtectedJwsJoseHeader(<JwsHeader>protectedHeaderOrHeaders);
        this.validateUnprotectedJwsJoseHeader(<JwsHeader>payloadOrUnprotectedHeader);

        this._checkIfProtectedAndUnprotectedHeadersAreDisjoint(
          <JwsHeader>protectedHeaderOrHeaders,
          <JwsHeader>payloadOrUnprotectedHeader,
        );

        this.protectedHeader = <JwsHeader>protectedHeaderOrHeaders;
        this.unprotectedHeader = <JwsHeader>payloadOrUnprotectedHeader;

        this.payload = payload;

        this.#serialization = 'flattened';

        break;

      default:
        throw new TypeError();
    }
  }

  /**
   * Checks if the provided data is a valid JSON Web Key Parameters object.
   *
   * @param data Data to be checked.
   * @returns Whether or not the provided data is a valid JSON Web Key Parameters object.
   */
  public static isJwsHeader(data: unknown): data is JwsHeader {
    return (
      Object.isPlain(data) &&
      Object.hasOwn(data, 'alg') &&
      typeof Reflect.get(data, 'alg') === 'string' &&
      Object.hasOwn(this.backends, Reflect.get(data, 'alg'))
    );
  }

  /**
   * Validates the provided Protected JWS JOSE Header.
   *
   * @param header Protected JWS JOSE Header.
   */
  private validateProtectedJwsJoseHeader(header: JwsHeader): void {
    this.validateJwsJoseHeader(header);
    JoseHeader.validateProtectedJoseHeader(header);
  }

  /**
   * Validates the provided Unprotected JWS JOSE Header.
   *
   * @param header Unprotected JWS JOSE Header.
   */
  private validateUnprotectedJwsJoseHeader(header: JwsHeader): void {
    this.validateJwsJoseHeader(header);
    JoseHeader.validateUnprotectedJoseHeader(header);
  }

  /**
   * Validates the provided JWS JOSE Header.
   *
   * @param header JWS JOSE Header.
   */
  private validateJwsJoseHeader(header: JwsHeader): void {
    if (typeof header.alg !== 'string' || !Object.hasOwn(JsonWebSignature.backends, header.alg)) {
      throw new InvalidJoseHeaderException('Invalid jose header parameter "alg".');
    }
  }

  private _checkIfProtectedAndUnprotectedHeadersAreDisjoint(
    protectedHeader?: JwsHeader,
    unprotectedHeader?: JwsHeader,
  ): void {
    if (
      Object.isPlain(protectedHeader) &&
      Object.isPlain(unprotectedHeader) &&
      !new Set(Object.keys(protectedHeader)).isDisjointFrom(new Set(Object.keys(unprotectedHeader)))
    ) {
      throw new InvalidJoseHeaderException('The protected and unprotected jose headers must be disjoint.');
    }
  }
}
