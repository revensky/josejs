import { Buffer } from 'buffer';
import { createPrivateKey, createPublicKey, sign, verify } from 'crypto';
import { promisify } from 'util';

import { InvalidJsonWebKeyException } from '../../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JwkKeyOp } from '../../../jwk/jwk.key-op';
import { JwkKty } from '../../../jwk/jwk.kty';
import { JwsAlg } from '../../../jws/jws.alg';
import { EcJwkParameters } from '../../jwk/ec/ec-jwk.parameters';
import { JwkCrv } from '../../jwk/jwk.crv';
import { JwsBackend } from '../jws.backend';

const signAsync = promisify(sign);
const verifyAsync = promisify(verify);

/**
 * Implementation of the ECDSA JSON Web Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4 | ECDSA JWS Algorithms}
 */
export abstract class ECDSAJwsBackend extends JwsBackend {
  /**
   * Name of the JSON Web Signature Algorithm used by the Backend.
   */
  protected abstract override readonly algorithm: JwsAlg;

  /**
   * Hash algorithm used to sign and verify messages.
   */
  protected abstract readonly hash: 'sha256' | 'sha384' | 'sha512';

  /**
   * Elliptic Curve used by the Backend.
   */
  protected abstract readonly curve: JwkCrv;

  /**
   * JSON Web Key Key Type supported by the Backend.
   */
  protected readonly keyType: JwkKty = 'EC';

  /**
   * Signs a Message with the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jwk JSON Web Key used to sign the provided message.
   * @returns Signature of the provided message.
   */
  public async sign(message: Buffer, jwk: JsonWebKey<EcJwkParameters>): Promise<Buffer> {
    this.validateJsonWebKey(jwk, 'sign');

    if (typeof jwk.parameters.d === 'undefined') {
      throw new InvalidJsonWebKeyException('Cannot use a public json web key for signing a message.');
    }

    return await signAsync(this.hash, message, createPrivateKey({ format: 'jwk', key: jwk.parameters }));
  }

  /**
   * Checks if the provided signature matches the provided message based on the provided JSON Web Key.
   *
   * @param signature Signature to be matched against the provided message.
   * @param message Message to be matched against the provided signature.
   * @param jwk JSON Web Key used to verify the signature and message.
   * @returns Whether the signature verification was successful.
   */
  public async verify(signature: Buffer, message: Buffer, jwk: JsonWebKey<EcJwkParameters>): Promise<boolean> {
    this.validateJsonWebKey(jwk, 'verify');

    return await verifyAsync(this.hash, message, createPublicKey({ format: 'jwk', key: jwk.parameters }), signature);
  }

  /**
   * Checks if the provided JSON Web Key can be used by the Backend.
   *
   * @param jwk JSON Web Key to be checked.
   * @param keyOp JSON Web Key Key Operation performed by the Backend.
   */
  protected override validateJsonWebKey(
    jwk: JsonWebKey<EcJwkParameters>,
    keyOp: Extract<JwkKeyOp, 'sign' | 'verify'>,
  ): void {
    if (jwk.parameters.crv !== this.curve) {
      throw new InvalidJsonWebKeyException(
        `The json web signature algorithm "${this.algorithm}" only accepts the elliptic curve "${this.curve}".`,
      );
    }

    super.validateJsonWebKey(jwk, keyOp);
  }
}
