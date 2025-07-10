import { Buffer } from 'buffer';

import { InvalidJsonWebKeyException } from '../../exceptions/invalid-jsonwebkey.exception';
import { JsonWebKey } from '../../jwk/jsonwebkey';
import { JwkKeyOp } from '../../jwk/jwk.key-op';
import { JwkKty } from '../../jwk/jwk.kty';
import { JwsAlg } from '../../jws/jws.alg';

/**
 * JSON Web Signature Backend.
 *
 * The JWS Backend is used to perform operations on the JSON Web Signature based on the JSON Web Signature Algorithm.
 */
export abstract class JwsBackend {
  /**
   * Name of the JSON Web Signature Algorithm used by the Backend.
   */
  protected abstract readonly algorithm: JwsAlg;

  /**
   * JSON Web Key Key Type supported by the Backend.
   */
  protected abstract readonly keyType: JwkKty;

  /**
   * Signs a Message with the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jwk JSON Web Key used to sign the provided message.
   * @returns Signature of the provided message.
   */
  public abstract sign(message: Buffer, jwk: JsonWebKey | null): Promise<Buffer>;

  /**
   * Checks if the provided signature matches the provided message based on the provided JSON Web Key.
   *
   * @param signature Signature to be matched against the provided message.
   * @param message Message to be matched against the provided signature.
   * @param jwk JSON Web Key used to verify the signature and message.
   * @returns Whether the signature verification was successful.
   */
  public abstract verify(signature: Buffer, message: Buffer, jwk: JsonWebKey | null): Promise<boolean>;

  /**
   * Checks if the provided JSON Web Key can be used by the Backend.
   *
   * @param jwk JSON Web Key to be checked.
   * @param keyOp JSON Web Key Key Operation performed by the Backend.
   */
  protected validateJsonWebKey(jwk: JsonWebKey, keyOp: Extract<JwkKeyOp, 'sign' | 'verify'>): void {
    if (jwk.parameters.kty !== this.keyType) {
      throw new InvalidJsonWebKeyException(
        `The json web signature algorithm "${this.algorithm}" only accepts "${this.keyType}" json web keys.`,
      );
    }

    if (typeof jwk.parameters.alg !== 'undefined' && jwk.parameters.alg !== this.algorithm) {
      throw new InvalidJsonWebKeyException(
        `This json web key is intended to be used by the json web signature algorithm "${jwk.parameters.alg}".`,
      );
    }

    if (
      (typeof jwk.parameters.use !== 'undefined' && jwk.parameters.use !== 'sig') ||
      (typeof jwk.parameters.key_ops !== 'undefined' && !jwk.parameters.key_ops.includes(keyOp))
    ) {
      throw new InvalidJsonWebKeyException('The provided json web key cannot be used by json web signatures.');
    }
  }
}
