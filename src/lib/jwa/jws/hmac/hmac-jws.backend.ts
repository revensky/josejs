import { Buffer } from 'buffer';
import { createHmac, createSecretKey, timingSafeEqual } from 'crypto';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JwkKeyOp } from '../../../jwk/jwk.key-op';
import { JwkKty } from '../../../jwk/jwk.kty';
import { JwsAlg } from '../../../jws/jws.alg';
import { OctJwkParameters } from '../../jwk/oct/oct-jwk.parameters';
import { JwsBackend } from '../jws.backend';

/**
 * Implementation of the HMAC JSON Web Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2 | HMAC JWS Algorithms}
 */
export abstract class HMACJwsBackend extends JwsBackend {
  /**
   * Name of the JSON Web Signature Algorithm used by the Backend.
   */
  protected abstract override readonly algorithm: JwsAlg;

  /**
   * Hash algorithm used to sign and verify messages.
   */
  protected abstract readonly hash: string;

  /**
   * Size of the secret accepted by the Backend.
   */
  protected abstract readonly keySize: number;

  /**
   * JSON Web Key Key Type supported by the Backend.
   */
  protected readonly keyType: JwkKty = 'oct';

  /**
   * Signs a Message with the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jwk JSON Web Key used to sign the provided message.
   * @returns Signature of the provided message.
   */
  public async sign(message: Buffer, jwk: JsonWebKey<OctJwkParameters>): Promise<Buffer> {
    this.validateJsonWebKey(jwk, 'sign');

    return createHmac(this.hash, createSecretKey(jwk.parameters.k, 'base64url')).update(message).digest();
  }

  /**
   * Checks if the provided signature matches the provided message based on the provided JSON Web Key.
   *
   * @param signature Signature to be matched against the provided message.
   * @param message Message to be matched against the provided signature.
   * @param jwk JSON Web Key used to verify the signature and message.
   * @returns Whether the signature verification was successful.
   */
  public async verify(signature: Buffer, message: Buffer, jwk: JsonWebKey<OctJwkParameters>): Promise<boolean> {
    this.validateJsonWebKey(jwk, 'verify');

    const calculatedSignature = await this.sign(message, jwk);

    return signature.length === calculatedSignature.length && timingSafeEqual(signature, calculatedSignature);
  }

  /**
   * Checks if the provided JSON Web Key can be used by the Backend.
   *
   * @param jwk JSON Web Key to be checked.
   * @param keyOp JSON Web Key Key Operation performed by the Backend.
   */
  protected override validateJsonWebKey(
    jwk: JsonWebKey<OctJwkParameters>,
    keyOp: Extract<JwkKeyOp, 'sign' | 'verify'>,
  ): void {
    if (Buffer.byteLength(jwk.parameters.k, 'base64url') < this.keySize) {
      throw new InvalidJsonWebKeyException(`The json web key parameter "k" must have at least ${this.keySize} bytes.`);
    }

    super.validateJsonWebKey(jwk, keyOp);
  }
}
