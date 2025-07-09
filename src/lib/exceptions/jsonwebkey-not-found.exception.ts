import { JoseException } from './jose.exception';

/**
 * Raised when no JSON Web Key matches the criteria at the JSON Web Key Set.
 */
export class JsonWebKeyNotFoundException extends JoseException {
  /**
   * Default JOSE Exception Error Message.
   */
  public override error: string = 'No JSON Web Key matches the criteria at the JSON Web Key Set.';
}
