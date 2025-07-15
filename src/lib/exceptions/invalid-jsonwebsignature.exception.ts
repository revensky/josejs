import { JoseException } from './jose.exception';

/**
 * Raised when the provided JSON Web Signature is invalid.
 */
export class InvalidJsonWebSignatureException extends JoseException {
  /**
   * Default JOSE Exception Error Message.
   */
  public override error: string = 'The provided JSON Web Signature is invalid.';
}
