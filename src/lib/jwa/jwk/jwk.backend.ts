import { JwkParameters } from '../../jwk/jwk.parameters';

/**
 * JSON Web Key Backend.
 *
 * The JWK Backend is used to perform operations on the JSON Web Key based on the JSON Web Key Type.
 */
export interface JwkBackend {
  /**
   * Validates the provided JSON Web Key Parameters.
   *
   * @param parameters JSON Web Key Parameters.
   */
  validate(parameters: JwkParameters): void;

  /**
   * Returns the Public JSON Web Key Parameters in lexical order to calculate the Thumbprint.
   *
   * @see {@link https://www.rfc-editor.org/rfc/rfc7638.html | JWK Thumbprint}
   *
   * @param parameters JSON Web Key Parameters.
   * @returns Public JSON Web Key Parameters for Thumbprint.
   */
  getThumbprintParameters(parameters: JwkParameters): JwkParameters;

  /**
   * Returns a list with the private parameters of the JSON Web Key.
   *
   * @returns JSON Web Key Private Parameters.
   */
  getPrivateParameters(): string[];
}
