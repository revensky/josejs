import { JoseException } from './jose.exception';

/**
 * Raised when the provided JSON Web Key Set is invalid.
 */
export class InvalidJsonWebKeySetException extends JoseException {
  /**
   * Instantiates a new Invalid JSON Web Key Set Exception.
   *
   * @param message Error Message.
   * @param options Error Options.
   */
  public constructor(message: string | null, options?: ErrorOptions) {
    super(message ?? 'The provided JSON Web Key Set is invalid.', options);
  }
}
