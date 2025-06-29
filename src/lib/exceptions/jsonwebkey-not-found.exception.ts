import { JoseException } from './jose.exception';

/**
 * Raised when no JSON Web Key matches the criteria at the JSON Web Key Set.
 */
export class JsonWebKeyNotFoundException extends JoseException {
  /**
   * Instantiates a new JSON Web Key Not Found Exception.
   */
  public constructor(options?: ErrorOptions) {
    super(undefined, options);
  }
}
