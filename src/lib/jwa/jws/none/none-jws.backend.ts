import { Buffer } from 'buffer';

import { JsonWebKey } from '../../../jwk/jsonwebkey';
import { JwkKeyOp } from '../../../jwk/jwk.key-op';
import { JwkKty } from '../../../jwk/jwk.kty';
import { JwsAlg } from '../../../jws/jws.alg';
import { JwsBackend } from '../jws.backend';

/**
 * Implementation of the none JSON Web Signature Backend.
 *
 * @see {@link https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6 | none JWS Algorithms}
 */
export class NoneJwsBackend extends JwsBackend {
  /**
   * Name of the JSON Web Signature Algorithm used by the Backend.
   */
  protected override readonly algorithm: JwsAlg = 'none';

  /**
   * JSON Web Key Key Type supported by the Backend.
   */
  protected readonly keyType: JwkKty = null!;

  /**
   * Signs a Message with the provided JSON Web Key.
   *
   * @param message Message to be signed.
   * @param jwk JSON Web Key used to sign the provided message.
   * @returns Signature of the provided message.
   */
  // @ts-expect-error
  public async sign(message: Buffer, jwk: null): Promise<Buffer> {
    return Buffer.alloc(0);
  }

  /**
   * Checks if the provided signature matches the provided message based on the provided JSON Web Key.
   *
   * @param signature Signature to be matched against the provided message.
   * @param message Message to be matched against the provided signature.
   * @param jwk JSON Web Key used to verify the signature and message.
   * @returns Whether the signature verification was successful.
   */
  // @ts-expect-error
  public async verify(signature: Buffer, message: Buffer, jwk: null): Promise<boolean> {
    return true;
  }

  /**
   * Checks if the provided JSON Web Key can be used by the Backend.
   *
   * @param jwk JSON Web Key to be checked.
   * @param keyOp JSON Web Key Key Operation performed by the Backend.
   */
  // @ts-expect-error
  protected override validateJsonWebKey(jwk: JsonWebKey, keyOp: Extract<JwkKeyOp, 'sign' | 'verify'>): void {}
}
