import { JsonWebKeyParameters } from '../jwk/jsonwebkey.parameters';

/**
 * Parameters of a JSON Web Key Set.
 */
export interface JsonWebKeySetParameters {
  /**
   * JSON Web Keys registered at the JSON Web Key Set.
   */
  keys: JsonWebKeyParameters[];
}
