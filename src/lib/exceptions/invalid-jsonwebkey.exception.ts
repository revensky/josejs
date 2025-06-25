import { JoseException } from './jose.exception';

/**
 * Raised when the provided JSON Web Key is invalid.
 */
export class InvalidJsonWebKeyException extends JoseException {
  /**
   * Instantiates a new Invalid JSON Web Key Exception.
   *
   * @param message Error Message.
   * @param options Error Options.
   */
  public constructor(message: string | null, options?: ErrorOptions) {
    super(message ?? 'The provided JSON Web Key is invalid.', options);
  }
}
