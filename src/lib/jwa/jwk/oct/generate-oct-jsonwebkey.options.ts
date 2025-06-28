/**
 * Octet Sequence JSON Web Key Generation Options.
 */
export interface GenerateOCTJsonWebKeyOptions extends Record<string, unknown> {
  /**
   * Length of the Secret in bytes.
   */
  readonly length: number;
}
