import { JoseException } from './jose.exception';

/**
 * Raised when the provided JOSE Header is invalid.
 */
export class InvalidJoseHeaderException extends JoseException {
  /**
   * Default JOSE Exception Error Message.
   */
  public override error: string = 'The provided JOSE Header is invalid.';
}
