import { JoseException } from './jose.exception';

/**
 * Raised when the provided JSON Web Key is invalid.
 */
export class InvalidJsonWebKeyException extends JoseException {
  /**
   * Default JOSE Exception Error Message.
   */
  public override error: string = 'The provided JSON Web Key is invalid.';
}
