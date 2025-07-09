import { JoseException } from './jose.exception';

/**
 * Raised when the provided JSON Web Key Set is invalid.
 */
export class InvalidJsonWebKeySetException extends JoseException {
  /**
   * Default JOSE Exception Error Message.
   */
  public override error: string = 'The provided JSON Web Key Set is invalid.';
}
