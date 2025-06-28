/**
 * RSA JSON Web Key Generation Options.
 */
export interface GenerateRSAJsonWebKeyOptions extends Record<string, unknown> {
  /**
   * Length of the Modulus of the key in bits.
   */
  readonly modulus: number;

  /**
   * Value of the Public Exponent of the key.
   *
   * @default 0x010001
   */
  readonly publicExponent?: number;
}
